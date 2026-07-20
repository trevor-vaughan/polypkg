package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
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
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

func newStatusCmd() *cobra.Command {
	var verbosity int
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show retained generations, drift, and GC preview",
		Long: "Default verbosity prints a one-line summary (generation, retention, drift, any freshness-grace count, any revoked-builder count, and any revocation-data expired/expiring-soon count). " +
			"-v adds per-generation listing, freshness-grace detail, and a revocation freshness section (each non-fresh source's expires with an [EXPIRED … ago] or [expiring in …] tag, plus [grace acknowledged] when an open grace window still covers an expired list); -vv adds drift detail and per-package attestation/revoked-builder tags; -vvv adds GC preview. " +
			"Exits 3 when an installed package's builder key has been revoked (as of the last fetch). " +
			"Exits 4 when an installed source's enforced revocation list is expired and not covered by an open accept_expiry_until grace window; the revoked-builder exit 3 takes precedence when both apply. " +
			"Under --format json the full StatusResult schema is always emitted and verbosity flags are ignored.",
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			err := runStatus(cmd, format, verbosity)
			if err != nil {
				var se *StatusError
				if errors.As(err, &se) {
					return err
				}
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

	stateHome, sherr := paths.UserStateHome()
	var grace []schema.StatusGraceEntry
	if sherr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: resolve state home for grace: %v\n", sherr)
	} else if g, gerr := collectGrace(stateHome, time.Now()); gerr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: freshness-grace inspect failed: %v\n", gerr)
	} else {
		grace = g
	}

	var revokedKeys map[string]struct{}
	if sherr == nil {
		if rk, rkerr := collectRevokedKeys(stateHome); rkerr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: revoked-builder inspect failed: %v\n", rkerr)
		} else {
			revokedKeys = rk
		}
	}

	var revFresh []schema.StatusRevocationFreshness
	if sherr == nil {
		threshold, terr := scopeNearExpiryThreshold("user", "")
		if terr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v (using 14d default)\n", terr)
			threshold = 14 * 24 * time.Hour
		}
		if rf, rferr := collectRevocationFreshness(stateHome, threshold, time.Now()); rferr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: revocation-freshness inspect failed: %v\n", rferr)
		} else {
			revFresh = rf
		}
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

	// Current-generation manifest feeds both the -vv package listing and the
	// revoked-builder check (which drives the default count + exit code), so load
	// it unconditionally; a missing/unreadable manifest degrades to nil.
	var curManifest *schema.Manifest
	if m, merr := readGenManifest(dataHome, cur); merr == nil {
		curManifest = m
	}
	revoked := collectRevokedBuilders(curManifest, revokedKeys)

	if format == FormatJSON {
		if err := emitStatusJSON(cmd.OutOrStdout(), cur, gens, driftEntries, decision, grace, revoked, revFresh); err != nil {
			return err
		}
	} else {
		emitStatusText(cmd.OutOrStdout(), verbosity, cur, gens, driftEntries, decision, curManifest, grace, revoked, revFresh)
	}
	if len(revoked) > 0 {
		return &StatusError{Code: 3, Quiet: true, Msg: "revoked builder key(s) on installed package(s)"}
	}
	for i := range revFresh {
		if revFresh[i].State == "expired" && !revFresh[i].Acknowledged {
			return &StatusError{Code: 4, Quiet: true, Msg: "revocation data expired for installed source(s)"}
		}
	}
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

// collectGrace reads the per-source freshness-grace markers recorded in the
// trust state at last fetch and returns them sorted by source. now is used to
// flag a window whose accept_expiry_until deadline has itself passed. A missing
// trust dir yields no entries.
func collectGrace(stateHome string, now time.Time) ([]schema.StatusGraceEntry, error) {
	sources, err := trust.ListSeenSources(stateHome)
	if err != nil {
		return nil, err
	}
	out := make([]schema.StatusGraceEntry, 0, len(sources))
	for _, source := range sources {
		seen, lerr := trust.LoadSeen(stateHome, source)
		if lerr != nil {
			return nil, fmt.Errorf("read grace for source %s: %w", source, lerr)
		}
		if seen.Graced == nil {
			continue
		}
		entry := schema.StatusGraceEntry{
			Source:      source,
			AcceptUntil: seen.Graced.AcceptUntil,
			Docs:        seen.Graced.Docs,
		}
		if t, perr := time.Parse(time.RFC3339, seen.Graced.AcceptUntil); perr == nil && now.After(t) {
			entry.WindowExpired = true
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out, nil
}

// collectRevokedKeys unions the revoked builder key IDs recorded per source in
// the trust state at last fetch. Best-effort: a read error is returned for the
// caller to warn on; a missing trust dir yields an empty set.
func collectRevokedKeys(stateHome string) (map[string]struct{}, error) {
	sources, err := trust.ListSeenSources(stateHome)
	if err != nil {
		return nil, err
	}
	out := map[string]struct{}{}
	for _, source := range sources {
		seen, lerr := trust.LoadSeen(stateHome, source)
		if lerr != nil {
			return nil, fmt.Errorf("read revoked keys for source %s: %w", source, lerr)
		}
		for _, k := range seen.RevokedBuilderKeys {
			out[k] = struct{}{}
		}
	}
	return out, nil
}

// collectRevocationFreshness classifies each source's enforced revocation list by the
// freshness of its last-fetched expires. threshold is the near-expiry window; now is
// passed for testability. Sources that never saw a revocation list
// (RevocationExpires == "") are skipped, as are ones with a comfortable margin. The
// expired boundary reuses trust.ExpirySkew so it matches the fetch path. Sorted by source.
func collectRevocationFreshness(stateHome string, threshold time.Duration, now time.Time) ([]schema.StatusRevocationFreshness, error) {
	sources, err := trust.ListSeenSources(stateHome)
	if err != nil {
		return nil, err
	}
	out := make([]schema.StatusRevocationFreshness, 0, len(sources))
	for _, source := range sources {
		seen, lerr := trust.LoadSeen(stateHome, source)
		if lerr != nil {
			return nil, fmt.Errorf("read revocation freshness for source %s: %w", source, lerr)
		}
		if seen.RevocationExpires == "" {
			continue
		}
		exp, perr := time.Parse(time.RFC3339, seen.RevocationExpires)
		if perr != nil {
			continue // defensive: fetch already validated it
		}
		var state string
		switch {
		case now.After(exp.Add(trust.ExpirySkew)):
			state = "expired"
		case now.After(exp.Add(-threshold)):
			state = "near_expiry"
		default:
			continue // fresh
		}
		entry := schema.StatusRevocationFreshness{Source: source, Expires: seen.RevocationExpires, State: state}
		if state == "expired" {
			entry.Acknowledged = revocationGraceAcknowledged(seen, now)
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out, nil
}

// revocationGraceAcknowledged reports whether an expired revocation list is covered by an
// OPEN operator grace window at status time: the last fetch graced the "revocation list"
// doc AND the accept_expiry_until deadline has not itself passed. Acknowledged expiry is
// informational and does not drive exit 4.
func revocationGraceAcknowledged(seen trust.Seen, now time.Time) bool {
	if seen.Graced == nil || !slices.Contains(seen.Graced.Docs, trust.DocRevocationList) {
		return false
	}
	t, err := time.Parse(time.RFC3339, seen.Graced.AcceptUntil)
	if err != nil {
		return false
	}
	return !now.After(t)
}

// collectRevokedBuilders returns the installed packages whose builder-verified
// binding was signed by a now-revoked builder key. De-duped per (package,
// version, key) and sorted for deterministic output. A nil manifest or empty
// revoked set yields none.
func collectRevokedBuilders(m *schema.Manifest, revoked map[string]struct{}) []schema.StatusRevokedBuilder {
	if m == nil || len(revoked) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []schema.StatusRevokedBuilder
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Attestation == nil {
			continue
		}
		for j := range e.Attestation.CarriedBindings {
			b := &e.Attestation.CarriedBindings[j]
			if b.Tier != schema.CarriedTierBuilderVerified || b.VerifyingKeyID == "" {
				continue
			}
			if _, ok := revoked[b.VerifyingKeyID]; !ok {
				continue
			}
			key := e.Name + "\x00" + e.Version + "\x00" + b.VerifyingKeyID
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, schema.StatusRevokedBuilder{Package: e.Name, Version: e.Version, KeyID: b.VerifyingKeyID})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].KeyID < out[j].KeyID
	})
	return out
}

// revokedKeyIDsFor returns the comma-joined revoked builder key IDs recorded for
// a given installed package (name@version), or "" if none.
func revokedKeyIDsFor(revoked []schema.StatusRevokedBuilder, name, version string) string {
	var ids []string
	for i := range revoked {
		if revoked[i].Package == name && revoked[i].Version == version {
			ids = append(ids, revoked[i].KeyID)
		}
	}
	return strings.Join(ids, ", ")
}

func emitStatusJSON(w io.Writer, cur int, gens []substrate.GenInfo,
	drifted []schema.PlanDriftEntry, dec gc.Decision, grace []schema.StatusGraceEntry,
	revoked []schema.StatusRevokedBuilder, revFresh []schema.StatusRevocationFreshness) error {
	sr := &schema.StatusResult{
		Schema:   "polypkg.status/v1",
		Current:  &schema.StatusCurrentGen{Generation: cur},
		Retained: make([]schema.StatusGenSummary, 0, len(gens)),
		Drift:    drifted,
		GCPreview: &schema.StatusGCPreview{
			WouldRemove: dec.Remove,
			WouldKeep:   dec.Keep,
		},
		FreshnessGrace:      grace,
		RevokedBuilders:     revoked,
		RevocationFreshness: revFresh,
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
	drifted []schema.PlanDriftEntry, dec gc.Decision, curManifest *schema.Manifest,
	grace []schema.StatusGraceEntry, revoked []schema.StatusRevokedBuilder,
	revFresh []schema.StatusRevocationFreshness) {
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
	graceSeg := ""
	if len(grace) > 0 {
		label := fmt.Sprintf("grace: %d source(s)", len(grace))
		expired := false
		for i := range grace {
			if grace[i].WindowExpired {
				expired = true
				break
			}
		}
		if expired {
			label = st.Changed.Render(label)
		} else {
			label = st.Emph.Render(label)
		}
		graceSeg = "  " + label
	}
	revokedSeg := ""
	if len(revoked) > 0 {
		revokedSeg = "  " + st.Changed.Render(fmt.Sprintf("revoked builders: %d package(s)", len(revoked)))
	}
	revFreshSeg := ""
	if len(revFresh) > 0 {
		nExpired, nNear := 0, 0
		for i := range revFresh {
			if revFresh[i].State == "expired" {
				nExpired++
			} else {
				nNear++
			}
		}
		label := fmt.Sprintf("revocation data: %d expired, %d expiring soon", nExpired, nNear)
		if nExpired > 0 {
			label = st.Changed.Render(label)
		} else {
			label = st.Emph.Render(label)
		}
		revFreshSeg = "  " + label
	}
	fmt.Fprintf(w, "current generation: %s  retained: %d (%d pinned)  drift: %s%s%s%s\n",
		st.Emph.Render(fmt.Sprintf("%d", cur)), len(gens), pinned, driftPart, graceSeg, revokedSeg, revFreshSeg)
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
	if len(grace) > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintf(w, "%s\n", st.Header.Render("freshness grace:"))
		for i := range grace {
			g := &grace[i]
			line := fmt.Sprintf("  %s: %s — accepted under grace until %s",
				g.Source, strings.Join(g.Docs, ", "), g.AcceptUntil)
			if g.WindowExpired {
				line += " " + st.Changed.Render("[window EXPIRED]")
			}
			fmt.Fprintln(w, line)
		}
	}
	if len(revFresh) > 0 {
		now := time.Now()
		fmt.Fprintln(w, "")
		fmt.Fprintf(w, "%s\n", st.Header.Render("revocation freshness:"))
		for i := range revFresh {
			r := &revFresh[i]
			exp, _ := time.Parse(time.RFC3339, r.Expires)
			var tag string
			if r.State == "expired" {
				tag = st.Changed.Render(fmt.Sprintf("[EXPIRED %s ago]", humanAge(now.Sub(exp))))
				if r.Acknowledged {
					tag += " [grace acknowledged]"
				}
			} else {
				tag = st.Emph.Render(fmt.Sprintf("[expiring in %s]", humanAge(exp.Sub(now))))
			}
			fmt.Fprintf(w, "  %s  expires %s  %s\n", r.Source, r.Expires, tag)
		}
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
			if ids := revokedKeyIDsFor(revoked, e.Name, e.Version); ids != "" {
				suffix += " " + st.Changed.Render("[builder revoked: "+ids+"]")
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
	case a.GateDisabled:
		return " [attestation gate OFF]"
	case a.Status == "verified":
		tag := " [attested]"
		if tiers := carriedTierSummary(a.CarriedBindings); tiers != "" {
			tag += " [carried: " + tiers + "]"
		}
		return tag
	case a.Status == "unattested":
		return " [unattested]"
	default:
		return ""
	}
}

// carriedTierSummary lists the DISTINCT tiers of a package's carried bindings,
// anchored tiers first, so a status reader never mistakes a verified-transport-only
// carried ref for a trusted one. Empty when there are no carried bindings.
func carriedTierSummary(bindings []schema.CarriedBinding) string {
	if len(bindings) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(bindings))
	var tiers []string
	for i := range bindings {
		t := bindings[i].Tier
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		tiers = append(tiers, t)
	}
	sort.Slice(tiers, func(i, j int) bool {
		ai, aj := tierAnchoredForDisplay(tiers[i]), tierAnchoredForDisplay(tiers[j])
		if ai != aj {
			return ai // anchored first
		}
		return tiers[i] < tiers[j]
	})
	return strings.Join(tiers, ", ")
}

// tierAnchoredForDisplay mirrors the planner's tierAnchored for ORDERING ONLY
// (that function is unexported in package planner); it confers no trust here.
func tierAnchoredForDisplay(tier string) bool {
	return tier == schema.CarriedTierBuilderVerified || tier == schema.CarriedTierVerifiedOffline
}
