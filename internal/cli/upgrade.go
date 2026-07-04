package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Masterminds/semver/v3"
	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/profileedit"
	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func newUpgradeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "upgrade [package...]",
		Aliases: []string{"update"},
		Short:   "Re-resolve the profile and bump exact pins to the newest version",
		Long: `Re-applies the profile so range-constrained packages pick up newer
versions, and reports exact pins ("=X.Y.Z") that a newer version is held back
behind.

With no arguments, upgrade re-applies without editing the profile: range
constraints re-resolve naturally, and each exact pin with a newer version
available is reported as held back.

With one or more package arguments, upgrade bumps each named exact pin to the
newest available version ("=<newest>") and applies. Range-constrained packages
named on the command line are re-resolved by the apply but their constraint is
left unchanged.

Validation is all-or-nothing: if any named package is not in the profile,
nothing is written.

Prerelease policy: a pin at a stable version (e.g. "=1.0.0") is never bumped
to a prerelease version (e.g. "2.0.0-rc1"), and is never reported as held back
behind one. Only if the current pin is itself a prerelease ("=2.0.0-rc1") are
newer prereleases eligible — the pin signals the operator has opted into the
prerelease track. This matches apt/dnf conservative-by-default behaviour.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "upgrade", runUpgrade(cmd, args, format))
		},
	}
	addScopeFlags(cmd)
	cmd.Flags().String("profile", "", "Profile file to edit (overrides scope-default discovery)")
	return cmd
}

// isPinned reports whether a profile constraint is an exact pin. Only an
// "="-prefixed constraint (e.g. "=1.0.0") is a pin; every range-y constraint
// (">=1.0.0", "^1.0", "~1.2", "*", "1.x", "") is not. The resolver accepts
// Masterminds semver constraints; the leading "=" is the sole pin marker the
// profile uses, mirroring how install writes a bare version as "=X".
func isPinned(constraint string) bool {
	return len(constraint) > 1 && constraint[0] == '='
}

// pinnedVersion returns the version a pin holds, stripping the leading "=".
// Only call on a constraint isPinned reports true for.
func pinnedVersion(constraint string) string {
	return constraint[1:]
}

// heldBackEntry is one pinned package the catalog has a newer version for than
// the pin allows: the apply keeps the pinned version, so the newer one is held
// back behind the pin until the operator bumps it.
type heldBackEntry struct {
	Name      string
	Pinned    string
	Available string
}

// newestLooker is the subset of resolver.Catalog the upgrade computations use:
// the newest candidate satisfying a constraint, plus the ordered version list
// for stable-only selection. Narrowing to this interface keeps the pure
// functions testable against a built catalog without coupling to the full
// Catalog surface.
type newestLooker interface {
	Newest(name, constraint string) (*resolver.Candidate, error)
	Versions(name string) []string
}

// newestStable returns the newest stable (non-prerelease) version of name from
// the catalog. It walks Versions (newest-first) and returns the first entry
// whose semver Prerelease() is empty. When no stable version exists it returns
// an error whose type matches KindNoVersion so callers treat it uniformly.
//
// Why not use Newest(name, ">=0.0.0-0") or similar? Masterminds' default range
// semantics exclude prereleases from range matches (confirmed: ">=1.0.0"
// returns false for "2.0.0-rc1"). The empty constraint in Newest is
// short-circuited to always-true in constraintAllows, so it matches all
// versions including prereleases. Therefore newestStable must filter in the
// CLI layer rather than leaning on a constraint string.
func newestStable(cat newestLooker, name string) (*resolver.Candidate, error) {
	for _, v := range cat.Versions(name) {
		sv, err := semver.NewVersion(v)
		if err != nil {
			return nil, fmt.Errorf("catalog: %s %q: %w", name, v, err)
		}
		if sv.Prerelease() == "" {
			return cat.Newest(name, "="+v)
		}
	}
	// No stable version; fall back to the absolute newest so callers can
	// surface a sensible no-stable-version error if they need to. Returning the
	// prerelease here is intentional: the caller (computeHeldBack /
	// decideUpgrade) checks whether the pin is stable before calling this
	// function, so this path is only reached when the whole catalog has only
	// prereleases for this package — an unusual but valid situation.
	return cat.Newest(name, "")
}

// computeHeldBack returns the held-back entries for the given scope packages:
// every pinned package whose catalog newest is strictly newer than the pin.
// Range-constrained packages are skipped — the apply re-resolves them, so
// nothing is held back. Entries are sorted by name for deterministic output.
// A catalog lookup failure (e.g. a pinned name absent from every source) is
// surfaced so the caller can report it rather than silently dropping the
// package.
//
// Prerelease policy: if the current pin is at a stable version, only stable
// catalog versions are considered; a pin at "=1.0.0" is never reported as held
// back behind "2.0.0-rc1". If the pin is itself prerelease ("=2.0.0-rc1"),
// the full catalog is used — the operator opted into the prerelease track.
func computeHeldBack(cat newestLooker, constraints map[string]string) ([]heldBackEntry, error) {
	var entries []heldBackEntry
	for name, constraint := range constraints {
		if !isPinned(constraint) {
			continue
		}
		pinVer := pinnedVersion(constraint)
		var cand *resolver.Candidate
		var err error
		if pinIsStable(pinVer) {
			cand, err = newestStable(cat, name)
		} else {
			cand, err = cat.Newest(name, "")
		}
		if err != nil {
			return nil, planExecError(err)
		}
		newer, err := versionGreater(cand.Version, pinVer)
		if err != nil {
			return nil, err
		}
		if newer {
			entries = append(entries, heldBackEntry{
				Name:      name,
				Pinned:    constraint,
				Available: cand.Version,
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

// pinIsStable reports whether the version string extracted from a pin (i.e.
// the part after "=") has no prerelease component. "1.0.0" → true,
// "2.0.0-rc1" → false. An unparseable version is conservatively treated as
// stable so the prerelease-exclusion heuristic never widens the upgrade
// candidate set on bad input.
func pinIsStable(version string) bool {
	sv, err := semver.NewVersion(version)
	if err != nil {
		return true
	}
	return sv.Prerelease() == ""
}

// versionGreater reports whether a is a strictly newer semver than b. Version
// comparison is always semver, never lexical string comparison, so "1.10.0"
// correctly sorts after "1.9.0".
func versionGreater(a, b string) (bool, error) {
	av, err := semver.NewVersion(a)
	if err != nil {
		return false, fmt.Errorf("parse version %q: %w", a, err)
	}
	bv, err := semver.NewVersion(b)
	if err != nil {
		return false, fmt.Errorf("parse version %q: %w", b, err)
	}
	return av.GreaterThan(bv), nil
}

// upgradeAction classifies what an argument-named package does on upgrade.
type upgradeAction string

const (
	upgradeBump     upgradeAction = "bump"      // pinned, newer available -> rewrite pin
	upgradeAtNewest upgradeAction = "at-newest" // pinned, already newest -> no edit
	upgradeRange    upgradeAction = "range"     // range constraint -> no edit, re-resolved
)

// upgradeDecision is the outcome of classifying one named package against the
// catalog: what action it implies and the constraint/version detail the
// caller renders or writes.
type upgradeDecision struct {
	Name          string
	Action        upgradeAction
	Constraint    string // the package's current profile constraint
	NewConstraint string // the pin to write, set only when Action == upgradeBump
	Available     string // catalog newest version (set for bump and at-newest)
}

// decideUpgrade classifies one named package: a pin with a newer version bumps
// to "=<newest>"; a pin already at the newest is kept; a range constraint is
// left alone but flagged so the caller includes it in the apply. A name absent
// from the catalog yields a typed resolve error.
//
// Prerelease policy: if the current pin is at a stable version, the catalog is
// queried for the newest stable release only — a stable pin can never be
// bumped to a prerelease. If the pin is itself a prerelease, the full catalog
// is used (the operator opted into the prerelease track).
func decideUpgrade(cat newestLooker, name, constraint string) (upgradeDecision, error) {
	if !isPinned(constraint) {
		return upgradeDecision{Name: name, Action: upgradeRange, Constraint: constraint}, nil
	}
	pinVer := pinnedVersion(constraint)
	var cand *resolver.Candidate
	var err error
	if pinIsStable(pinVer) {
		cand, err = newestStable(cat, name)
	} else {
		cand, err = cat.Newest(name, "")
	}
	if err != nil {
		return upgradeDecision{}, planExecError(err)
	}
	newer, err := versionGreater(cand.Version, pinVer)
	if err != nil {
		return upgradeDecision{}, err
	}
	if !newer {
		return upgradeDecision{
			Name:       name,
			Action:     upgradeAtNewest,
			Constraint: constraint,
			Available:  cand.Version,
		}, nil
	}
	return upgradeDecision{
		Name:          name,
		Action:        upgradeBump,
		Constraint:    constraint,
		NewConstraint: "=" + cand.Version,
		Available:     cand.Version,
	}, nil
}

// heldBackLine renders one held-back report line. House style uses a semicolon,
// never an em dash, between the status and the follow-up command.
func heldBackLine(e heldBackEntry) string {
	return fmt.Sprintf(
		"held back: %s %s (%s available); run `polypkg upgrade %s` to bump the pin",
		e.Name, e.Pinned, e.Available, e.Name)
}

// runUpgrade implements the upgrade command. The no-args form re-applies the
// profile and reports held-back pins without editing; the args form bumps each
// named pin (validating all names first) and applies. Both need the catalog and
// a later apply, so each acquires the apply lock, fetches the catalog, releases
// the lock, and lets applyProfile re-acquire it.
func runUpgrade(cmd *cobra.Command, args []string, format Format) error {
	profilePath, err := installProfilePath(cmd)
	if err != nil {
		return err
	}

	p, err := parseProfileAt(cmd, profilePath)
	if err != nil {
		return err
	}

	scope, prefix, err := resolveScope(cmd, p)
	if err != nil {
		return err
	}
	_, stateHome, err := scopeHomes(scope, prefix)
	if err != nil {
		return err
	}

	constraints := profilePackageNames(p, scope)

	if len(args) == 0 {
		return runUpgradeAll(cmd, format, scope, stateHome, profilePath, p, constraints)
	}
	return runUpgradeNamed(cmd, format, scope, stateHome, profilePath, p, constraints, args)
}

// fetchUpgradeCatalog acquires the apply lock, fetches and verifies the catalog
// (forcing the fetch so a profile with no in-scope packages still resolves),
// then releases the lock so applyProfile can re-acquire it. The TOCTOU window
// between release and apply is acceptable: applyProfile re-fetches and
// re-verifies the catalog.
func fetchUpgradeCatalog(
	cmd *cobra.Command,
	scope, stateHome string,
	p *schema.Profile,
) (*planner.FetchResult, error) {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := os.MkdirAll(stateHome, scopeDirMode(scope)); err != nil {
		return nil, fmt.Errorf("create state home: %w", err)
	}

	lockPath := filepath.Join(stateHome, "apply.lock")
	l, lerr := lock.Acquire(ctx, lockPath, lock.Options{TxID: "upgrade", Command: "polypkg upgrade"})
	if lerr != nil {
		return nil, lockError(lockPath, lerr)
	}
	defer func() { _ = l.Release() }()

	fr, fetchErr := planner.FetchCatalog(ctx, p, planner.Options{
		StateHome:         stateHome,
		Scope:             scope,
		ForceCatalogFetch: true,
	})
	if fetchErr != nil {
		return nil, planExecError(fetchErr)
	}
	return fr, nil
}

// runUpgradeAll handles the no-args form: re-apply the profile and report
// held-back pins. The profile is never edited. An empty in-scope package set is
// a CLIError naming install.
func runUpgradeAll(
	cmd *cobra.Command,
	format Format,
	scope, stateHome, profilePath string,
	p *schema.Profile,
	constraints map[string]string,
) error {
	if len(constraints) == 0 {
		return &CLIError{
			Msg:  "the profile has no packages to upgrade",
			Hint: "add packages with `polypkg install <name>` first",
		}
	}

	fr, err := fetchUpgradeCatalog(cmd, scope, stateHome, p)
	if err != nil {
		return err
	}
	if fr.Catalog == nil {
		// ForceCatalogFetch was set, so a non-empty package set always yields a
		// catalog; a nil catalog here means the profile requests nothing for this
		// scope, which the len(constraints)==0 guard already rejected.
		return &CLIError{
			Msg:  "the profile has no packages to upgrade",
			Hint: "add packages with `polypkg install <name>` first",
		}
	}

	held, err := computeHeldBack(fr.Catalog, constraints)
	if err != nil {
		return err
	}

	out, applyErr := applyProfile(cmd, profilePath, false, false)
	if applyErr != nil {
		return applyErr
	}

	emitUpgradeAllResult(cmd, format, held, out)
	return nil
}

// runUpgradeNamed handles the args form: validate every named package is in the
// profile, classify each against the catalog, write any pin bumps, and apply.
// If no edits result and nothing range-y was named, exit 0 with the reports and
// no apply.
func runUpgradeNamed(
	cmd *cobra.Command,
	format Format,
	scope, stateHome, profilePath string,
	p *schema.Profile,
	constraints map[string]string,
	args []string,
) error {
	if verr := validateUpgradeNames(args, constraints, scope); verr != nil {
		return verr
	}

	fr, err := fetchUpgradeCatalog(cmd, scope, stateHome, p)
	if err != nil {
		return err
	}
	if fr.Catalog == nil {
		// Named packages are present in the profile (validated above), so the
		// forced fetch must have produced a catalog. A nil catalog is a real
		// source failure rather than the empty-profile case.
		return &CLIError{
			Msg:  "no catalog is available from any configured source",
			Hint: "check the sources in your profile",
		}
	}

	decisions := make([]upgradeDecision, len(args))
	for i, name := range args {
		d, derr := decideUpgrade(fr.Catalog, name, constraints[name])
		if derr != nil {
			return derr
		}
		decisions[i] = d
	}

	pending := make([]profileedit.Edit, 0, len(decisions))
	anyRange := false
	for _, d := range decisions {
		switch d.Action {
		case upgradeBump:
			pending = append(pending, profileedit.Edit{Scope: scope, Name: d.Name, Version: d.NewConstraint})
		case upgradeRange:
			anyRange = true
		}
	}

	// No pin bumps and nothing range-y to re-resolve: report and exit without an
	// apply (matches install's all-kept no-apply path).
	if len(pending) == 0 && !anyRange {
		emitUpgradeNamedNoApply(cmd, format, decisions)
		return nil
	}

	var original []byte
	if len(pending) > 0 {
		original, err = writeEditsUnderLock(cmd, stateHome, profilePath, scope, "upgrade", "polypkg upgrade", pending)
		if err != nil {
			return err
		}
	}

	out, applyErr := applyProfile(cmd, profilePath, false, false)
	if applyErr != nil {
		if original != nil {
			return restoreOnFailure(profilePath, original, applyErr, "upgrade")
		}
		return applyErr
	}

	emitUpgradeNamedResult(cmd, format, decisions, out)
	return nil
}

// validateUpgradeNames returns a CLIError if any named package is absent from
// the profile scope. The check is all-or-nothing: the first missing name
// terminates early, mirroring remove's validation and hint shape.
func validateUpgradeNames(names []string, known map[string]string, scope string) error {
	for _, name := range names {
		if _, ok := known[name]; !ok {
			knownNames := make([]string, 0, len(known))
			for k := range known {
				knownNames = append(knownNames, k)
			}
			sort.Strings(knownNames)
			return &CLIError{
				Msg:  fmt.Sprintf("%s is not in the profile", name),
				Hint: knownPackageHint(knownNames, scope),
			}
		}
	}
	return nil
}

// renderUpgradeDecisions writes the per-package report lines for the args form.
func renderUpgradeDecisions(w *bytes.Buffer, decisions []upgradeDecision) {
	for _, d := range decisions {
		switch d.Action {
		case upgradeBump:
			fmt.Fprintf(w, "bumping %s pin: %q -> %q\n", d.Name, d.Constraint, d.NewConstraint)
		case upgradeAtNewest:
			fmt.Fprintf(w, "%s is already at the newest version (%s)\n", d.Name, d.Available)
		case upgradeRange:
			fmt.Fprintf(w, "%s follows %q; apply re-resolves it\n", d.Name, d.Constraint)
		}
	}
}

// heldBackData builds the JSON data list for held-back entries.
func heldBackData(held []heldBackEntry) []any {
	list := make([]any, len(held))
	for i, e := range held {
		list[i] = map[string]any{
			"name":      e.Name,
			"pinned":    e.Pinned,
			"available": e.Available,
		}
	}
	return list
}

// upgradeDecisionsData builds the JSON edits list for the args form.
func upgradeDecisionsData(decisions []upgradeDecision) []any {
	list := make([]any, len(decisions))
	for i, d := range decisions {
		entry := map[string]any{
			"name":   d.Name,
			"action": string(d.Action),
		}
		if d.Action == upgradeBump {
			entry["constraint"] = d.NewConstraint
		}
		if d.Available != "" {
			entry["available"] = d.Available
		}
		list[i] = entry
	}
	return list
}

// emitUpgradeAllResult emits the no-args result: the apply output followed by
// one held-back line per entry. JSON gains held_back plus the apply's gen_id
// and host data.
func emitUpgradeAllResult(cmd *cobra.Command, format Format, held []heldBackEntry, out *applyOutcome) {
	data := out.data()
	data["held_back"] = heldBackData(held)
	EmitResult(cmd, format, "upgrade", data, func(w *bytes.Buffer, _ map[string]any) {
		out.renderText(w, nil)
		for _, e := range held {
			fmt.Fprintln(w, heldBackLine(e))
		}
	})
}

// emitUpgradeNamedResult emits the args-form result after an apply: the
// per-package report lines plus the apply output. JSON gains the edit list and
// the apply's gen_id and host data.
func emitUpgradeNamedResult(cmd *cobra.Command, format Format, decisions []upgradeDecision, out *applyOutcome) {
	data := out.data()
	data["edits"] = upgradeDecisionsData(decisions)
	EmitResult(cmd, format, "upgrade", data, func(w *bytes.Buffer, _ map[string]any) {
		renderUpgradeDecisions(w, decisions)
		out.renderText(w, nil)
	})
}

// emitUpgradeNamedNoApply emits the args-form result when no pin was bumped and
// nothing range-y was named, so no apply ran. There is no gen_id in the JSON
// envelope: gen_id is only present when an apply succeeds and produces a new
// generation. Consumers must treat gen_id as optional — its absence here is
// intentional, not an error.
func emitUpgradeNamedNoApply(cmd *cobra.Command, format Format, decisions []upgradeDecision) {
	data := map[string]any{"edits": upgradeDecisionsData(decisions)}
	EmitResult(cmd, format, "upgrade", data, func(w *bytes.Buffer, _ map[string]any) {
		renderUpgradeDecisions(w, decisions)
	})
}
