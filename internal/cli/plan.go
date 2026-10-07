package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/alternatives"
	"github.com/trevor-vaughan/polypkg/internal/cli/style"
	"github.com/trevor-vaughan/polypkg/internal/conflict"
	"github.com/trevor-vaughan/polypkg/internal/diff"
	"github.com/trevor-vaughan/polypkg/internal/drift"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/starlarkeval"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// errPlanChangesPending exits 2 ("changes pending", terraform
// -detailed-exitcode convention) without an error envelope or stderr
// line — the complete plan result is already the stdout body.
// Sentinel: matched by pointer identity via errors.Is — do not add an Is method to StatusError.
var errPlanChangesPending = &StatusError{Code: 2, Quiet: true, Msg: "changes pending"}

func newPlanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plan [profile-file]",
		Short: "Compute and diff the apply plan against the current state",
		Long: "Loads packages per the profile, fetches and verifies artifacts, compares against the " +
			"current generation, and reports drift. Exit codes: 0 = no changes, 2 = changes pending, 1 = error.\n\n" +
			"With no profile-file argument, uses the default profile: POLYPKG_PROFILE\n" +
			"if set, else profile.{yaml,yml,jsonc,json} in the scope's config directory\n" +
			"(user: ~/.config/polypkg; system: /etc/polypkg).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			profilePath, perr := resolveProfilePath(cmd, args)
			if perr != nil {
				return WrapError(cmd, format, "plan", perr)
			}
			err := runPlan(cmd, profilePath, format)
			if errors.Is(err, errPlanChangesPending) {
				// Return the sentinel so cobra exits non-zero, but do NOT
				// emit an error envelope — the complete plan/v1 result has
				// already been written.
				return err
			}
			return WrapError(cmd, format, "plan", err)
		},
	}
	addScopeFlags(cmd)
	cmd.Flags().Bool("no-recommends", false, "Do not install weak dependencies (Recommends) for this run")
	return cmd
}

func runPlan(cmd *cobra.Command, profilePath string, format Format) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	f, err := openProfileFile(cmd, profilePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	p, err := schema.ParseProfile(f, profilePath)
	if err != nil {
		// ParseProfile errors already name the file; no wrap needed.
		return err
	}

	noRec, _ := cmd.Flags().GetBool("no-recommends")
	weakPolicy := effectiveWeakPolicy(p.Recommends, noRec)

	scope, prefix, err := resolveScope(cmd, p)
	if err != nil {
		return err
	}
	nearExpiry, nerr := scopeNearExpiryThreshold(scope, prefix)
	if nerr != nil {
		return &StatusError{Code: 1, Msg: nerr.Error()}
	}
	dataHome, stateHome, err := scopeHomes(scope, prefix)
	if err != nil {
		return err
	}

	// Pre-create only the state home at the scope dir mode, before
	// lock.Acquire — it MkdirAlls stateHome at 0o700, and for system scope
	// stateHome IS the substrate root, so it would pin an un-traversable root
	// (MkdirAll never chmods an existing dir). plan keeps its data side
	// read-only — it must not create the substrate data root as an empty dir
	// (the read-only-open invariant); for system scope stateHome is the root, so
	// it still gets the traversable mode here, while the data tree (generations)
	// is created later only by apply. plan never opens the audit log: it is a
	// preview, and apply records every decision when it takes effect.
	if err := os.MkdirAll(stateHome, scopeDirMode(scope)); err != nil {
		return fmt.Errorf("create state home: %w", err)
	}

	scopeSpec, ok := p.Scopes[scope]
	if !ok {
		return &CLIError{
			Msg:  fmt.Sprintf("profile has no %q scope (profile defines: %s)", scope, scopeNamesStr(p)),
			Hint: fmt.Sprintf("add a scopes.%s section to the profile, or pass --scope with a defined scope", scope),
		}
	}
	sub, err := substrate.New(scopeSpec.Substrate, dataHome)
	if err != nil {
		return fmt.Errorf("open substrate: %w", err)
	}

	// planner.Plan advances the per-source trust serial; acquire the apply
	// lock to serialize against concurrent applies.
	lockPath := filepath.Join(stateHome, "apply.lock")
	l, err := lock.Acquire(ctx, lockPath,
		lock.Options{TxID: "plan", Command: "polypkg plan"})
	if err != nil {
		return lockError(lockPath, err)
	}
	defer func() { _ = l.Release() }()

	// Read the diff baseline (current generation's ownership and active root)
	// before planning so the projection can expand $ACTIVE against the same
	// active root the runner used at apply time — without it, target-carrying
	// actions (path/symlink/...) project the literal "$ACTIVE/..." and false-diff
	// against the stored absolute target forever.
	priorOwn, gen, activeRoot, oerr := sub.CurrentOwnership()

	rl := schema.ResolveStarlarkLimits(p.Starlark)
	// Posture floor (2d-2): load the current generation's manifest so Plan can
	// preview a provenance-regression refusal. Best-effort; nil disables it.
	var priorManifest *schema.Manifest
	if oerr == nil && gen > 0 {
		if pm, merr := readGenManifest(dataHome, gen); merr == nil {
			priorManifest = pm
		}
	}
	res, err := planner.Plan(ctx, p, planner.Options{
		DataHome:   dataHome,
		StateHome:  stateHome,
		Scope:      scope,
		WeakPolicy: weakPolicy,
		StarlarkLimits: starlarkeval.Limits{
			MaxSteps:       rl.MaxSteps,
			Timeout:        time.Duration(rl.Timeout),
			MaxMemoryBytes: rl.MaxMemoryBytes,
			MaxOutputBytes: rl.MaxOutputBytes,
		},
		BaselineActiveRoot:   activeRoot, // "" when oerr != nil; projection keeps the placeholder
		AttestationPolicy:    attestationPolicy(p),
		PriorManifest:        priorManifest,
		RevocationNearExpiry: nearExpiry,
		DirMode:              scopeDirMode(scope),
	})
	if err != nil {
		return planExecError(err)
	}
	for _, warn := range res.AttestationWarnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", warn)
	}
	for _, gd := range res.AttestationGateDisabled {
		fmt.Fprintf(cmd.ErrOrStderr(), "SECURITY: attestation gate disabled (tier: off) for %s (source %s) — would install without require/posture enforcement\n", gd.Package, gd.Source)
	}
	for _, g := range res.FreshnessGraced {
		fmt.Fprintf(cmd.ErrOrStderr(), "SECURITY: %s %s metadata expired — would install under grace until %s (freshness relaxed; anti-rollback still enforced)\n", g.Source, g.What, g.AcceptUntil)
	}
	for _, n := range res.NearExpiry {
		fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: %s %s expires %s (within near-expiry window) — publisher should re-sign\n", n.Source, n.What, n.Expires)
	}

	if conflicts := conflict.Detect(res.Ownership.Entries); len(conflicts) > 0 {
		return &CLIError{
			Msg:  fmt.Sprintf("shared-path conflict: %s", conflict.Summary(conflicts)),
			Hint: "give the commands distinct names, or expose the command via the alternatives action (priority-arbitrated) instead of path",
		}
	}

	var (
		priorMan     *schema.Manifest
		driftEntries []schema.PlanDriftEntry
		currentGen   int
	)

	switch {
	case errors.Is(oerr, substrate.ErrNoCurrentGeneration):
		priorOwn = nil
	case oerr != nil:
		// Corrupt or unreadable current state: warn, proceed with nil baseline.
		fmt.Fprintf(cmd.ErrOrStderr(), "warn: %v\n", oerr)
		priorOwn = nil
	default:
		currentGen = gen
		if pm, merr := readGenManifest(dataHome, gen); merr == nil {
			priorMan = pm
		}
		drifted, derr := drift.Inspect(priorOwn, activeRoot)
		if derr == nil {
			var altDrifted []drift.Entry
			altDrifted, derr = drift.InspectAlternatives(priorOwn, activeRoot, sub.AltRoot(), alternatives.SelectionsPath(sub.StateRoot()))
			if derr == nil {
				drifted = append(drifted, altDrifted...)
			}
		}
		if derr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warn: drift inspect: %v\n", derr)
		} else {
			driftEntries = make([]schema.PlanDriftEntry, 0, len(drifted))
			for i := range drifted {
				d := &drifted[i]
				driftEntries = append(driftEntries, schema.PlanDriftEntry{
					Path:         d.Owned.Path,
					Action:       d.Owned.Action,
					Reason:       string(d.Reason),
					Policy:       d.Owned.DriftPolicy,
					PriorHash:    d.Owned.Expected.ContentHash,
					ObservedHash: d.Observed,
				})
			}
		}
	}

	d := diff.Diff(priorMan, priorOwn, res.Manifest, res.Ownership)
	exitCode := 0
	if !d.NoChanges || len(driftEntries) > 0 {
		exitCode = 2
	}

	if format == FormatJSON {
		pr := schema.PlanResult{
			Schema:            "polypkg.plan/v1",
			Profile:           profilePath,
			Packages:          toPlanPackageDiff(d.Packages),
			Ownership:         toPlanOwnershipDiff(d.Ownership),
			Drift:             driftEntries,
			SkippedRecommends: toPlanSkipped(res.Skipped),
			Suggests:          toPlanSuggests(res.Suggests),
			Exit:              exitCode,
		}
		if currentGen != 0 {
			pr.Current = &schema.PlanCurrentGen{Generation: currentGen}
		}
		data, _ := json.Marshal(&pr)
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
	} else {
		renderPlanText(cmd.OutOrStdout(), profilePath, currentGen, d, driftEntries, res.Skipped, res.Suggests)
	}

	if exitCode != 0 {
		return errPlanChangesPending
	}
	return nil
}

// attestationPolicy resolves the profile's attestation posture; absent → warn
// (the D8 default: unattested installs are permitted with knowledge).
func attestationPolicy(p *schema.Profile) string {
	if p.Attestation != nil && p.Attestation.Policy != "" {
		return p.Attestation.Policy
	}
	return "warn"
}

func renderPlanText(w io.Writer, profile string, currentGen int, d diff.Result, drifted []schema.PlanDriftEntry, skipped []resolver.SkippedRecommend, suggests []resolver.Suggestion) {
	st := style.ForWriter(w)
	fmt.Fprintf(w, "%s\n", st.Header.Render("plan: "+profile))
	if currentGen == 0 {
		fmt.Fprintln(w, "  no current generation (first apply)")
	} else {
		fmt.Fprintf(w, "  current generation: %d\n", currentGen)
	}
	if d.NoChanges && len(drifted) == 0 && len(skipped) == 0 && len(suggests) == 0 {
		fmt.Fprintln(w, "  no changes pending")
		return
	}
	if d.NoChanges && len(drifted) == 0 {
		fmt.Fprintln(w, "  no changes pending")
	}
	if len(d.Packages.Added) > 0 {
		fmt.Fprintf(w, "  %s\n", st.Header.Render("added packages:"))
		for i := range d.Packages.Added {
			p := &d.Packages.Added[i]
			fmt.Fprintf(w, "    %s\n", st.Added.Render("+ "+p.Name+" "+p.Version))
		}
	}
	if len(d.Packages.Removed) > 0 {
		fmt.Fprintf(w, "  %s\n", st.Header.Render("removed packages:"))
		for i := range d.Packages.Removed {
			p := &d.Packages.Removed[i]
			fmt.Fprintf(w, "    %s\n", st.Removed.Render("- "+p.Name+" "+p.Version))
		}
	}
	if len(d.Packages.Upgraded) > 0 {
		fmt.Fprintf(w, "  %s\n", st.Header.Render("upgraded packages:"))
		for _, v := range d.Packages.Upgraded {
			fmt.Fprintf(w, "    %s\n", st.Changed.Render(v.Name+" "+v.OldVersion+" -> "+v.NewVersion))
		}
	}
	if len(d.Packages.Downgraded) > 0 {
		fmt.Fprintf(w, "  %s\n", st.Header.Render("downgraded packages:"))
		for _, v := range d.Packages.Downgraded {
			fmt.Fprintf(w, "    %s\n", st.Changed.Render(v.Name+" "+v.OldVersion+" -> "+v.NewVersion))
		}
	}
	if len(d.Ownership.Added)+len(d.Ownership.Removed)+len(d.Ownership.Changed) > 0 {
		fmt.Fprintf(w, "  %s\n", st.Header.Render("ownership changes:"))
		for i := range d.Ownership.Added {
			e := &d.Ownership.Added[i]
			fmt.Fprintf(w, "    %s\n", st.Added.Render("+ "+e.Path+" ("+e.Action+" by "+e.Package+")"))
		}
		for i := range d.Ownership.Removed {
			e := &d.Ownership.Removed[i]
			fmt.Fprintf(w, "    %s\n", st.Removed.Render("- "+e.Path+" ("+e.Action+" by "+e.Package+")"))
		}
		for i := range d.Ownership.Changed {
			c := &d.Ownership.Changed[i]
			fmt.Fprintf(w, "    %s\n", st.Changed.Render("~ "+c.Path+" ("+c.Action+" by "+c.Package+")"))
		}
	}
	if len(drifted) > 0 {
		fmt.Fprintf(w, "  %s\n", st.Header.Render("drift detected on current generation:"))
		for _, e := range drifted {
			fmt.Fprintf(w, "    %s\n", st.Changed.Render(e.Path+": "+e.Reason+" ("+e.Action+")"))
		}
	}
	renderWeakSummary(w, st, skipped, suggests)
}

// renderWeakSummary writes the skipped-recommend and suggested-package sections
// shared by plan and apply text output. st must be the value returned by
// style.ForWriter(w) so rendering decisions (TTY color vs. plain) stay
// consistent with the surrounding output.
func renderWeakSummary(w io.Writer, st style.Styles, skipped []resolver.SkippedRecommend, suggests []resolver.Suggestion) {
	if len(skipped) > 0 {
		fmt.Fprintf(w, "  %s\n", st.Header.Render("skipped recommended packages:"))
		for _, s := range skipped {
			line := "~ " + s.Name + " (" + s.Reason + ")"
			if len(s.RecommendedBy) > 0 {
				line += " recommended by " + strings.Join(s.RecommendedBy, ", ")
			}
			fmt.Fprintf(w, "    %s\n", st.Changed.Render(line))
		}
	}
	if len(suggests) > 0 {
		fmt.Fprintf(w, "  %s\n", st.Header.Render("suggested (not installed):"))
		for _, s := range suggests {
			line := s.Name
			if s.SuggestedBy != "" {
				line += " (suggested by " + s.SuggestedBy + ")"
			}
			fmt.Fprintf(w, "    %s\n", st.Changed.Render(line))
		}
	}
}

func toPlanPackageDiff(p diff.PackageDiff) schema.PlanPackageDiff {
	out := schema.PlanPackageDiff{
		Added:   p.Added,
		Removed: p.Removed,
	}
	for _, v := range p.Upgraded {
		out.Upgraded = append(out.Upgraded, schema.PlanVersionChange(v))
	}
	for _, v := range p.Downgraded {
		out.Downgraded = append(out.Downgraded, schema.PlanVersionChange(v))
	}
	return out
}

func toPlanOwnershipDiff(o diff.OwnershipDiff) schema.PlanOwnershipDiff {
	out := schema.PlanOwnershipDiff{
		Added:   o.Added,
		Removed: o.Removed,
	}
	for i := range o.Changed {
		out.Changed = append(out.Changed, schema.PlanOwnershipChange(o.Changed[i]))
	}
	return out
}

func toPlanSkipped(in []resolver.SkippedRecommend) []schema.PlanSkippedRecommend {
	if len(in) == 0 {
		return nil
	}
	out := make([]schema.PlanSkippedRecommend, 0, len(in))
	for _, s := range in {
		out = append(out, schema.PlanSkippedRecommend{
			Name:          s.Name,
			VersionRange:  s.VersionRange,
			Reason:        s.Reason,
			RecommendedBy: s.RecommendedBy,
		})
	}
	return out
}

func toPlanSuggests(in []resolver.Suggestion) []schema.PlanSuggestion {
	if len(in) == 0 {
		return nil
	}
	out := make([]schema.PlanSuggestion, 0, len(in))
	for _, s := range in {
		out = append(out, schema.PlanSuggestion{
			Name:         s.Name,
			VersionRange: s.VersionRange,
			SuggestedBy:  s.SuggestedBy,
		})
	}
	return out
}
