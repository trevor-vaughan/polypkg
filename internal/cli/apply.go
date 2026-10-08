package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/action"
	"github.com/trevor-vaughan/polypkg/internal/audit"
	"github.com/trevor-vaughan/polypkg/internal/bridge"
	"github.com/trevor-vaughan/polypkg/internal/cli/style"
	"github.com/trevor-vaughan/polypkg/internal/gc"
	"github.com/trevor-vaughan/polypkg/internal/linkfarm"
	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/runner"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/starlarkeval"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

func newApplyCmd() *cobra.Command {
	var healDrift, noDriftCheck bool
	cmd := &cobra.Command{
		Use:   "apply [profile-file]",
		Short: "Apply a profile spec",
		Long: `Applies the profile so the system matches it, creating a new generation.

With no profile-file argument, applies the default profile: POLYPKG_PROFILE
if set, else profile.{yaml,yml,jsonc,json} in the scope's config directory
(user: ~/.config/polypkg; system: /etc/polypkg).`,
		Args: needsArgs(0, 1, "at most one [profile-file]"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApply(cmd, args, healDrift, noDriftCheck)
		},
		ValidArgsFunction: func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
			return []string{"yaml", "yml"}, cobra.ShellCompDirectiveFilterFileExt
		},
	}
	cmd.Flags().BoolVar(&healDrift, "heal-drift", false, "Overwrite drifted files with the profile's version instead of refusing the apply")
	cmd.Flags().BoolVar(&noDriftCheck, "no-drift-check", false, "Skip drift detection entirely (only safe when drift cannot occur)")
	cmd.Flags().Bool("no-recommends", false, "Do not install weak dependencies (Recommends) for this run")
	addScopeFlags(cmd)
	return cmd
}

func runApply(cmd *cobra.Command, args []string, healDrift, noDriftCheck bool) error {
	format, ferr := resolveFormat(cmd)
	if ferr != nil {
		return ferr
	}
	profilePath, err := resolveProfilePath(cmd, args)
	if err != nil {
		return WrapError(cmd, format, "apply", err)
	}
	return WrapError(cmd, format, "apply", runApplyInner(cmd, profilePath, healDrift, noDriftCheck))
}

// runApplyInner runs the apply pipeline for profilePath and emits the apply
// command's result envelope. It is the apply verb's body; install reuses
// applyProfile directly and emits its own envelope.
func runApplyInner(cmd *cobra.Command, profilePath string, healDrift, noDriftCheck bool) error {
	out, err := applyProfile(cmd, profilePath, healDrift, noDriftCheck)
	if err != nil {
		return err
	}
	format, _ := resolveFormat(cmd)
	EmitResult(cmd, format, "apply", out.data(), out.renderText)
	return nil
}

// applyOutcome carries the result of a completed apply run: the generation id
// and the host-integration data the result envelope reports. Both the apply
// and install verbs build their envelope from it (apply renders it verbatim;
// install prepends its edit summary).
type applyOutcome struct {
	gen int

	// weak dependency summary forwarded from planner.Result
	skipped  []resolver.SkippedRecommend
	suggests []resolver.Suggestion

	bridgeRes bridge.Result
	binDir    string
	bridged   bool

	compRes  map[string]linkfarm.Result
	compDirs map[string]string
	comped   bool

	deskRes linkfarm.Result
	deskDir string
	desked  bool

	mimeRes linkfarm.Result
	mimeDir string
	mimed   bool

	manNudge bool
	manDir   string
}

// data builds the cli-result data map for the host-integration portion of an
// apply, keyed identically for the apply and install envelopes. Callers that
// need extra keys (install: edits) add them to the returned map.
func (o *applyOutcome) data() map[string]any {
	data := map[string]any{"gen_id": o.gen}
	if len(o.skipped) > 0 {
		data["skipped_recommends"] = toPlanSkipped(o.skipped)
	}
	if len(o.suggests) > 0 {
		data["suggests"] = toPlanSuggests(o.suggests)
	}
	if o.bridged {
		data["bridge"] = map[string]any{
			"linked": o.bridgeRes.Linked, "pruned": o.bridgeRes.Pruned, "skipped": skippedNames(o.bridgeRes),
		}
	}
	if o.comped {
		data["completion"] = completionResultData(o.compRes)
	}
	if o.desked {
		data["desktop"] = map[string]any{
			"linked": o.deskRes.Linked, "pruned": o.deskRes.Pruned, "skipped": skippedNames(o.deskRes),
		}
	}
	if o.mimed {
		data["mime"] = map[string]any{
			"linked": o.mimeRes.Linked, "pruned": o.mimeRes.Pruned, "skipped": skippedNames(o.mimeRes),
		}
	}
	if o.manNudge {
		data["manpath"] = o.manDir
	}
	return data
}

// renderText writes the applied-generation line, host-integration summary, and
// weak dependency summary for apply text output. Shared by the apply and
// install text renderers (install writes its edit summary before calling this).
func (o *applyOutcome) renderText(w *bytes.Buffer, _ map[string]any) {
	fmt.Fprintf(w, "applied generation %d\n", o.gen)
	o.renderHostText(w)
	renderWeakSummary(w, style.ForWriter(w), o.skipped, o.suggests)
}

// renderHostText writes only the host-integration summary lines (no
// applied-generation line). install reuses it after its own generation line.
func (o *applyOutcome) renderHostText(w *bytes.Buffer) {
	if o.bridged {
		writeBridgeSummary(w, o.bridgeRes, o.binDir)
	}
	if o.comped {
		writeCompletionSummary(w, o.compRes, o.compDirs)
	}
	if o.desked {
		writeDesktopSummary(w, o.deskRes, o.deskDir)
	}
	if o.mimed {
		writeMimeSummary(w, o.mimeRes, o.mimeDir)
	}
	if o.manNudge {
		fmt.Fprintln(w, manNudgeLine(o.manDir))
	}
}

// applyProfile runs the full apply pipeline for profilePath: parse, plan,
// acquire the apply lock (inside the runner), execute, and run host
// integration. It returns the outcome the caller renders into an envelope.
// It emits nothing itself, so callers must not hold the apply lock when they
// call it (the runner re-acquires it).
func applyProfile(cmd *cobra.Command, profilePath string, healDrift, noDriftCheck bool) (*applyOutcome, error) {
	ctx := cmd.Context()

	// Progress goes to stderr in text mode (TTY: spinner; non-TTY: plain lines).
	// Under --format json, suppress progress entirely so it cannot pollute the
	// structured output stream on non-TTY stderr. newProgress(nil) is a no-op.
	format, _ := resolveFormat(cmd)
	var progWriter io.Writer
	if format != FormatJSON {
		progWriter = cmd.ErrOrStderr()
	}
	prog := newProgress(progWriter)
	defer prog.Done()

	f, err := openProfileFile(cmd, profilePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	p, err := schema.ParseProfile(f, profilePath)
	if err != nil {
		// ParseProfile errors already name the file; no wrap needed.
		return nil, err
	}

	noRec, _ := cmd.Flags().GetBool("no-recommends")
	weakPolicy := effectiveWeakPolicy(p.Recommends, noRec)

	scope, prefix, err := resolveScope(cmd, p)
	if err != nil {
		return nil, err
	}
	nearExpiry, nerr := scopeNearExpiryThreshold(scope, prefix)
	if nerr != nil {
		return nil, nerr
	}
	dataHome, stateHome, err := scopeHomes(scope, prefix)
	if err != nil {
		return nil, err
	}
	dirMode := scopeDirMode(scope)

	// System scope: pin the process umask so every directory created during this
	// apply lands at its exact declared mode regardless of the operator's
	// inherited umask. A restrictive root umask (0o027/0o077) would otherwise
	// strip the group/other traversal bits a multi-user install needs, silently
	// defeating the 0o755 dir modes. Explicit 0o600/0o644 file modes and the
	// 0o700 private subtrees are unaffected by a 0o022 umask. Restored on return.
	if scope == "system" {
		defer setUmask(0o022)()
	}

	// Pre-create the scoped homes at the scope dir mode BEFORE the audit writer.
	// audit.NewFileWriter MkdirAll's its parent at 0o700, and for system scope
	// stateHome == dataHome == the substrate root; letting audit create it 0o700
	// first would pin an un-traversable root (MkdirAll never chmods an existing
	// dir). For user scope dirMode is 0o700 — identical to today's behavior.
	if err := os.MkdirAll(dataHome, dirMode); err != nil {
		return nil, fmt.Errorf("create data home: %w", err)
	}
	if err := os.MkdirAll(stateHome, dirMode); err != nil {
		return nil, fmt.Errorf("create state home: %w", err)
	}

	scopeSpec, ok := p.Scopes[scope]
	if !ok {
		return nil, &CLIError{
			Msg:  fmt.Sprintf("profile has no %q scope (profile defines: %s)", scope, scopeNamesStr(p)),
			Hint: fmt.Sprintf("add a scopes.%s section to the profile, or pass --scope with a defined scope", scope),
		}
	}
	sub, err := substrate.New(scopeSpec.Substrate, dataHome, substrate.WithDirMode(dirMode))
	if err != nil {
		return nil, fmt.Errorf("open substrate: %w", err)
	}

	auditPath := filepath.Join(stateHome, "audit.log")
	w, err := audit.NewFileWriter(auditPath)
	if err != nil {
		return nil, fmt.Errorf("open audit writer: %w", err)
	}
	defer func() { _ = w.Close() }()

	rl := schema.ResolveStarlarkLimits(p.Starlark)
	starlarkLimits := starlarkeval.Limits{
		MaxSteps:       rl.MaxSteps,
		Timeout:        time.Duration(rl.Timeout),
		MaxMemoryBytes: rl.MaxMemoryBytes,
		MaxOutputBytes: rl.MaxOutputBytes,
	}

	// Posture floor: load the current generation's manifest so Plan can
	// refuse a provenance regression. Best-effort — a first apply (no active
	// generation) or an unreadable manifest yields nil, disabling the floor.
	var priorManifest *schema.Manifest
	if gen, gerr := sub.CurrentGeneration(); gerr == nil && gen > 0 {
		if pm, merr := readGenManifest(dataHome, gen); merr == nil {
			priorManifest = pm
		}
	}

	planRes, err := planner.Plan(ctx, p, planner.Options{
		DataHome:             dataHome,
		StateHome:            stateHome,
		Scope:                scope,
		WeakPolicy:           weakPolicy,
		StarlarkLimits:       starlarkLimits,
		Progress:             prog.Update,
		AttestationPolicy:    attestationPolicy(p),
		PriorManifest:        priorManifest,
		RevocationNearExpiry: nearExpiry,
		DirMode:              dirMode,
		// apply never reads planRes.Ownership; the runner records the real one.
		SkipMultiResultProjection: true,
	})
	if err != nil {
		return nil, planExecError(err)
	}
	for _, warn := range planRes.AttestationWarnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", warn)
	}
	for _, gd := range planRes.AttestationGateDisabled {
		fmt.Fprintf(cmd.ErrOrStderr(), "SECURITY: attestation gate disabled (tier: off) for %s (source %s) — installed without require/posture enforcement\n", gd.Package, gd.Source)
		_ = w.Write(audit.Event{
			Scope: scope, TxID: "apply", Event: "attestation.gate_off",
			Fields: map[string]any{"package": gd.Package, "source": gd.Source},
		})
	}
	for _, g := range planRes.FreshnessGraced {
		fmt.Fprintf(cmd.ErrOrStderr(), "SECURITY: %s %s metadata expired — accepted under grace until %s (freshness relaxed; anti-rollback still enforced)\n", g.Source, g.What, g.AcceptUntil)
		_ = w.Write(audit.Event{
			Scope: scope, TxID: "apply", Event: "metadata.expiry_graced",
			Fields: map[string]any{"source": g.Source, "metadata": g.What, "accept_expiry_until": g.AcceptUntil},
		})
	}
	for _, n := range planRes.NearExpiry {
		fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: %s %s expires %s (within near-expiry window) — publisher should re-sign\n", n.Source, n.What, n.Expires)
	}
	entries := planRes.Entries

	// Apply overwrites ProducedBy with the real CLI version and apply
	// timestamp (planner sets a placeholder Version="dev" and no Timestamp).
	host, _ := os.Hostname()
	m := planRes.Manifest
	m.ProducedBy = schema.ProducedBy{
		Tool:      "polypkg",
		Version:   Version,
		Timestamp: time.Now().UTC(),
		Host:      host,
	}

	if err := validatePlacementPhases(entries); err != nil {
		return nil, err
	}

	// Retention: profile > hardcoded user-scope default (5 / 30d).
	const (
		defaultRetentionCount = 5
		defaultRetentionAge   = "30d"
	)
	retCount, retAgeStr := defaultRetentionCount, defaultRetentionAge
	if p.Retention != nil {
		if p.Retention.Count > 0 {
			retCount = p.Retention.Count
		}
		if p.Retention.Age != "" {
			retAgeStr = p.Retention.Age
		}
	}
	retAge, err := gc.ParseAge(retAgeStr)
	if err != nil {
		return nil, fmt.Errorf("retention.age: %w", err)
	}
	gcPolicy := &gc.Policy{Count: retCount, Age: retAge}
	if err := gcPolicy.Validate(); err != nil {
		return nil, err
	}

	r := runner.New(runner.Options{
		Substrate:         sub,
		AuditWriter:       w,
		Scope:             scope,
		DirMode:           dirMode,
		LockPath:          filepath.Join(stateHome, "apply.lock"),
		StarlarkLimits:    starlarkLimits,
		HealDrift:         healDrift,
		NoDriftCheck:      noDriftCheck,
		AcceptedDriftPath: filepath.Join(stateHome, "accepted-drift.json"),
		ResetsPath:        filepath.Join(stateHome, "pending-resets.json"),
		GCPolicy:          gcPolicy,
		Progress:          prog.Update,
	})
	applyLockPath := filepath.Join(stateHome, "apply.lock")
	gen, err := r.Run(ctx, m, entries)
	if err != nil {
		// The runner wraps its lock error as "acquire lock: ..."; translate
		// that into a CLIError so the user sees holder info instead of an
		// opaque "run: acquire lock: lock is held by another process".
		if isLockConflictError(err) {
			return nil, lockError(applyLockPath, err)
		}
		return nil, fmt.Errorf("run: %w", err)
	}

	// Opportunistic store sweep: generation GC just ran inside the runner, so
	// extract dirs and cached downloads referenced only by pruned generations
	// are now garbage.
	_ = sweepStores(sub, stateHome, cmd.ErrOrStderr())

	out := &applyOutcome{
		gen:      gen,
		skipped:  planRes.Skipped,
		suggests: planRes.Suggests,
	}
	// Host integration runs for both scopes: user -> ~/.local/bin etc.,
	// system -> <prefix>/usr/local/* (each helper resolves the scope-appropriate
	// host dirs + config gate and, for system scope, pre-creates the host dir at
	// the scope mode). Still best-effort: a reconcile failure is a warning, never
	// a failed apply.
	prog.Update("linking", "")
	out.bridgeRes, out.binDir, out.bridged = runBridgeReconcile(sub, scope, prefix)
	out.compRes, out.compDirs, out.comped = runCompletionReconcile(sub, scope, prefix)
	out.deskRes, out.deskDir, out.desked = runDesktopReconcile(sub, scope, prefix)
	out.mimeRes, out.mimeDir, out.mimed = runMimeReconcile(sub, scope, prefix)
	out.manNudge = manFollowersPresent(sub)
	if out.manNudge {
		out.manDir = sub.ActiveManDir()
	}
	return out, nil
}

// validatePlacementPhases enforces that file-placing actions are declared only in
// pre-swap phases. A file-placing action in a post-swap phase would be materialized
// after the ownership index is written at commit, so it could never be tracked
// for drift — reject it before any transaction begins.
func validatePlacementPhases(entries []runner.RunEntry) error {
	for _, e := range entries {
		for _, v := range e.Package.Actions {
			if action.IsFilePlacing(v.Action) && !action.IsPreSwapPhase(v.Phase) {
				return fmt.Errorf(
					"package %q declares file-placing action %q in post-swap phase %q; "+
						"file-placing actions (install, symlink, dir, perms) must run in a pre-swap phase "+
						"(pre-place, post-place, pre-activate)",
					e.Package.Name, v.Action, v.Phase)
			}
		}
	}
	return nil
}
