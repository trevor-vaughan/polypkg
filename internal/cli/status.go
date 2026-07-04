package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/alternatives"
	"github.com/trevor-vaughan/polypkg/internal/cli/style"
	"github.com/trevor-vaughan/polypkg/internal/drift"
	"github.com/trevor-vaughan/polypkg/internal/gc"
	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

func newStatusCmd() *cobra.Command {
	var verbosity int
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show retained generations, drift, and GC preview",
		Long: "Default verbosity prints a one-line summary. " +
			"-v adds per-generation listing; -vv adds drift detail; -vvv adds GC preview. " +
			"Under --format json the full StatusResult schema is always emitted and verbosity flags are ignored.",
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			err := runStatus(cmd, format, verbosity)
			if err != nil {
				return WrapError(cmd, format, "status", err)
			}
			return nil
		},
	}
	cmd.Flags().CountVarP(&verbosity, "verbose", "v",
		"Increase output detail (-v list, -vv +drift, -vvv +gc preview)")
	return cmd
}

func runStatus(cmd *cobra.Command, format Format, verbosity int) error {
	dataHome, err := paths.UserDataHome()
	if err != nil {
		return err
	}
	sub, err := substrate.NewOwnStore(dataHome)
	if err != nil {
		return err
	}

	cur, curErr := sub.CurrentGeneration()
	if curErr != nil {
		// No current generation: emit the first-apply view in either format.
		if format == FormatJSON {
			sr := &schema.StatusResult{
				Schema:   "polypkg.status/v1",
				Retained: []schema.StatusGenSummary{},
			}
			data, merr := json.Marshal(sr)
			if merr != nil {
				return fmt.Errorf("marshal status-result: %w", merr)
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(data))
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "no generation applied yet — apply a profile to get started")
		}
		return nil
	}

	gens, err := sub.ListGenerations()
	if err != nil {
		return fmt.Errorf("list generations: %w", err)
	}
	sort.Slice(gens, func(i, j int) bool { return gens[i].ID < gens[j].ID })

	driftEntries, derr := collectDrift(sub)
	if derr != nil {
		// Drift inspection is observational; failures must not abort status. A
		// nil slice degrades gracefully and the summary line reports 0 entries.
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: drift inspect failed: %v\n", derr)
	}

	// GC preview uses the user-scope defaults (5 / 30d), matching the default
	// retention applied by opportunistic GC when a profile specifies none.
	policy := gc.Policy{Count: 5, Age: 30 * 24 * time.Hour}
	algGens := make([]gc.Generation, 0, len(gens))
	for i := range gens {
		g := &gens[i]
		algGens = append(algGens, gc.Generation{
			ID:          g.ID,
			CommittedAt: g.CommittedAt,
			Pinned:      g.Pinned,
			IsCurrent:   g.IsCurrent,
		})
	}
	decision := gc.Decide(algGens, policy, time.Now())

	if format == FormatJSON {
		return emitStatusJSON(cmd.OutOrStdout(), cur, gens, driftEntries, decision)
	}

	// Load the manifest for the current generation so emitStatusText can list
	// packages with weak annotations under -vv.  A missing/unreadable manifest
	// degrades gracefully (nil is accepted by emitStatusText).
	var curManifest *schema.Manifest
	if verbosity >= 2 {
		if m, merr := readGenManifest(dataHome, cur); merr == nil {
			curManifest = m
		}
	}

	emitStatusText(cmd.OutOrStdout(), verbosity, cur, gens, driftEntries, decision, curManifest)
	return nil
}

// collectDrift reads the current ownership index and inspects the live active
// root. ErrNoCurrentGeneration is converted to a nil result (first apply has
// no baseline). Any other failure is returned so the caller can warn.
func collectDrift(sub *substrate.OwnStore) ([]schema.PlanDriftEntry, error) {
	priorOwn, _, activeRoot, oerr := sub.CurrentOwnership()
	if errors.Is(oerr, substrate.ErrNoCurrentGeneration) {
		return nil, nil
	}
	if oerr != nil {
		return nil, fmt.Errorf("read current ownership: %w", oerr)
	}
	drifted, derr := drift.Inspect(priorOwn, activeRoot)
	if derr != nil {
		return nil, fmt.Errorf("inspect drift: %w", derr)
	}
	altDrifted, aerr := drift.InspectAlternatives(priorOwn, activeRoot, sub.AltRoot(), alternatives.SelectionsPath(sub.StateRoot()))
	if aerr != nil {
		return nil, fmt.Errorf("inspect alternatives drift: %w", aerr)
	}
	drifted = append(drifted, altDrifted...)
	out := make([]schema.PlanDriftEntry, 0, len(drifted))
	for i := range drifted {
		d := &drifted[i]
		out = append(out, schema.PlanDriftEntry{
			Path:         d.Owned.Path,
			Action:       d.Owned.Action,
			Reason:       string(d.Reason),
			Policy:       d.Owned.DriftPolicy,
			PriorHash:    d.Owned.Expected.ContentHash,
			ObservedHash: d.Observed,
		})
	}
	return out, nil
}

func emitStatusJSON(w io.Writer, cur int, gens []substrate.GenInfo,
	drifted []schema.PlanDriftEntry, dec gc.Decision) error {
	sr := &schema.StatusResult{
		Schema:   "polypkg.status/v1",
		Current:  &schema.StatusCurrentGen{Generation: cur},
		Retained: make([]schema.StatusGenSummary, 0, len(gens)),
		Drift:    drifted,
		GCPreview: &schema.StatusGCPreview{
			WouldRemove: dec.Remove,
			WouldKeep:   dec.Keep,
		},
	}
	for i := range gens {
		g := &gens[i]
		sr.Retained = append(sr.Retained, schema.StatusGenSummary{
			ID:           g.ID,
			CommittedAt:  g.CommittedAt,
			Pinned:       g.Pinned,
			PinnedReason: g.PinnedReason,
			IsCurrent:    g.IsCurrent,
			BytesOnDisk:  g.BytesOnDisk,
		})
	}
	data, err := json.Marshal(sr)
	if err != nil {
		return fmt.Errorf("marshal status-result: %w", err)
	}
	fmt.Fprintln(w, string(data))
	return nil
}

func emitStatusText(w io.Writer, verbosity, cur int, gens []substrate.GenInfo,
	drifted []schema.PlanDriftEntry, dec gc.Decision, curManifest *schema.Manifest) {
	st := style.ForWriter(w)
	pinned := 0
	for i := range gens {
		if gens[i].Pinned {
			pinned++
		}
	}
	driftPart := fmt.Sprintf("%d entries", len(drifted))
	if len(drifted) > 0 {
		driftPart = st.Changed.Render(driftPart)
	}
	fmt.Fprintf(w, "current generation: %s  retained: %d (%d pinned)  drift: %s\n",
		st.Emph.Render(fmt.Sprintf("%d", cur)), len(gens), pinned, driftPart)
	if verbosity < 1 {
		return
	}
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "%s\n", st.Header.Render("retained generations:"))
	for i := range gens {
		g := &gens[i]
		marker := " "
		if g.IsCurrent {
			marker = st.Emph.Render("*")
		}
		genID := fmt.Sprintf("%d", g.ID)
		if g.IsCurrent {
			genID = st.Emph.Render(genID)
		}
		pin := ""
		if g.Pinned {
			pin = " [pinned"
			if g.PinnedReason != "" {
				pin += ": " + g.PinnedReason
			}
			pin += "]"
		}
		age := "?"
		if !g.CommittedAt.IsZero() {
			age = humanAge(time.Since(g.CommittedAt)) + " ago"
		}
		fmt.Fprintf(w, "  %s %s  %s  %d bytes%s\n", marker, genID, age, g.BytesOnDisk, pin)
	}
	if verbosity < 2 {
		return
	}
	// Under -vv: list current generation's packages, flagging weak entries.
	if curManifest != nil && len(curManifest.Entries) > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintf(w, "%s\n", st.Header.Render("installed packages (current generation):"))
		for i := range curManifest.Entries {
			e := &curManifest.Entries[i]
			suffix := attestationTag(e.Attestation)
			if e.Weak {
				suffix += " [weak]"
				if len(e.RecommendedBy) > 0 {
					suffix += " recommended by " + strings.Join(e.RecommendedBy, ", ")
				}
			}
			fmt.Fprintf(w, "  %s %s%s\n", e.Name, e.Version, suffix)
		}
	}
	if len(drifted) > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintf(w, "%s\n", st.Header.Render("drift detail:"))
		for i := range drifted {
			d := &drifted[i]
			fmt.Fprintf(w, "  %s (%s): %s [policy: %s]\n", d.Path, d.Action, d.Reason, d.Policy)
		}
	}
	if verbosity < 3 {
		return
	}
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "%s\n", st.Header.Render("GC preview (default policy 5/30d):"))
	fmt.Fprintf(w, "  would keep:   %v\n", dec.Keep)
	fmt.Fprintf(w, "  would remove: %v\n", dec.Remove)
}

// humanAge renders d at its largest whole unit (s/m/h/d). The previous
// Round(time.Hour).String() rendering collapsed everything under 30 minutes
// to "0s ago". Negative durations (clock skew) clamp to "0s".
func humanAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	}
}

// attestationTag renders the -vv package-listing suffix for a manifest
// entry's install-time attestation record (D11): " [attested]" when it
// verified, " [unattested]" when it installed without one, and nothing when
// the record is absent (generation predates the v2 attestation chain).
func attestationTag(a *schema.AttestationState) string {
	switch {
	case a == nil:
		return ""
	case a.Status == "verified":
		return " [attested]"
	case a.Status == "unattested":
		return " [unattested]"
	default:
		return ""
	}
}
