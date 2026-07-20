package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List installed packages in the current generation",
		Long: `Shows every package installed in the current generation, with its resolved
version and whether it is exact-pinned in the profile. Exits with a friendly
message when no generation has been applied yet.

Pass --scope system to inspect the system-scope store.`,
		Example: "  # List all installed packages\n" +
			"  polypkg list\n\n" +
			"  # List as JSON (for scripting)\n" +
			"  polypkg list -f json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "list", runList(cmd, format))
		},
	}
	addScopeFlags(cmd)
	return cmd
}

func newInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "info <package>",
		Aliases: []string{"show"},
		Short:   "Show installed and available versions for a package",
		Long: `Fetches the catalog and displays the installed version (if any), all available
versions from the configured source, and which artifact would be downloaded for
the newest. Degrades gracefully when offline: if the package is installed,
the installed information is shown with a note that available versions are unknown.`,
		Example: "  polypkg info hello",
		Args:    needsArgs(1, 1, "<package>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "info", runInfo(cmd, args[0], format))
		},
	}
	addScopeFlags(cmd)
	return cmd
}

// runList implements the list command. It is read-only: no lock is acquired.
func runList(cmd *cobra.Command, format Format) error {
	p := bestEffortProfile(cmd)
	scope, dataHome, _, err := resolveListScope(cmd, p)
	if err != nil {
		return err
	}

	sub, err := substrate.New("store", dataHome)
	if err != nil {
		return fmt.Errorf("open substrate: %w", err)
	}

	_, gen, _, oerr := sub.CurrentOwnership()
	if errors.Is(oerr, substrate.ErrNoCurrentGeneration) {
		return emitListEmpty(cmd, format)
	}
	if oerr != nil {
		return fmt.Errorf("read current state: %w", oerr)
	}

	manifest, merr := readGenManifest(dataHome, gen)
	if merr != nil {
		return fmt.Errorf("read manifest: %w", merr)
	}

	// Load pins from the already-parsed profile.
	pins := profilePins(p, scope)

	return emitListResult(cmd, format, scope, gen, manifest, pins)
}

// withCatalog resolves the profile, takes the apply lock, fetches the
// catalog, and hands it to fn. Used by search only; runInfo intentionally
// bypasses this helper because its offline-tolerance fallback needs the
// profile resolved before any lock is taken.
//
// scope and stateHome are resolved from cmd before the call. txID and command
// are passed to lock.Acquire so the lock metadata names the owning verb (e.g.
// "search"). fn receives the parsed profile, its resolved path, and
// the FetchResult; it must not call Release on the lock.
func withCatalog(
	cmd *cobra.Command,
	scope, stateHome string,
	txID, command string,
	fn func(p *schema.Profile, profilePath string, fr *planner.FetchResult) error,
) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	profilePath, perr := resolveProfilePath(cmd, nil)
	if perr != nil {
		return perr
	}

	f, ferr := openProfileFile(cmd, profilePath)
	if ferr != nil {
		return ferr
	}
	p, perr2 := schema.ParseProfile(f, profilePath)
	_ = f.Close()
	if perr2 != nil {
		return perr2
	}

	if err := os.MkdirAll(stateHome, scopeDirMode(scope)); err != nil {
		return fmt.Errorf("create state home: %w", err)
	}

	lockPath := filepath.Join(stateHome, "apply.lock")
	l, err := lock.Acquire(ctx, lockPath,
		lock.Options{TxID: txID, Command: command})
	if err != nil {
		return lockError(lockPath, err)
	}
	defer func() { _ = l.Release() }()

	fr, fetchErr := planner.FetchCatalog(ctx, p, planner.Options{
		StateHome:         stateHome,
		Scope:             scope,
		ForceCatalogFetch: true,
	})
	if fetchErr != nil {
		return planExecError(fetchErr)
	}

	return fn(p, profilePath, fr)
}

// runInfo implements the info command.
func runInfo(cmd *cobra.Command, pkgName string, format Format) error {
	p := bestEffortProfile(cmd)
	scope, dataHome, stateHome, err := resolveListScope(cmd, p)
	if err != nil {
		return err
	}

	sub, err := substrate.New("store", dataHome)
	if err != nil {
		return fmt.Errorf("open substrate: %w", err)
	}

	// Read installed version (read-only, no lock needed).
	installedVersion := ""
	installedGen := 0
	var installedAtt *schema.AttestationState
	_, gen, _, oerr := sub.CurrentOwnership()
	if oerr == nil {
		manifest, merr := readGenManifest(dataHome, gen)
		if merr == nil {
			for i := range manifest.Entries {
				if manifest.Entries[i].Name == pkgName {
					installedVersion = manifest.Entries[i].Version
					installedGen = gen
					installedAtt = manifest.Entries[i].Attestation
					break
				}
			}
		}
	}

	// Fetch available versions from the catalog (requires the apply lock per
	// FetchCatalog's contract). withCatalog returns the profile-not-found
	// CLIError when no profile is configured; detect and handle offline
	// tolerance before calling it.
	profilePath, perr := resolveProfilePath(cmd, nil)
	if perr != nil {
		if installedVersion != "" {
			// Offline tolerance: no profile → show installed info only.
			return emitInfoResult(cmd, format, pkgName, scope, installedVersion, installedGen,
				nil, "", "no profile found", nil, nil, nil, installedAtt)
		}
		return perr
	}

	f, ferr := openProfileFile(cmd, profilePath)
	if ferr != nil {
		if installedVersion != "" {
			return emitInfoResult(cmd, format, pkgName, scope, installedVersion, installedGen,
				nil, "", "profile unreadable", nil, nil, nil, installedAtt)
		}
		return ferr
	}
	p, perr2 := schema.ParseProfile(f, profilePath)
	_ = f.Close()
	if perr2 != nil {
		if installedVersion != "" {
			return emitInfoResult(cmd, format, pkgName, scope, installedVersion, installedGen,
				nil, "", "profile parse error", nil, nil, nil, installedAtt)
		}
		return perr2
	}

	if err := os.MkdirAll(stateHome, scopeDirMode(scope)); err != nil {
		return fmt.Errorf("create state home: %w", err)
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	lockPath := filepath.Join(stateHome, "apply.lock")
	l, err := lock.Acquire(ctx, lockPath,
		lock.Options{TxID: "info", Command: "polypkg info"})
	if err != nil {
		return lockError(lockPath, err)
	}
	defer func() { _ = l.Release() }()

	fr, fetchErr := planner.FetchCatalog(ctx, p, planner.Options{
		StateHome:         stateHome,
		Scope:             scope,
		ForceCatalogFetch: true,
	})

	if fetchErr != nil {
		if installedVersion != "" {
			// Offline tolerance: show what we know, note unreachable source.
			note := "source unreachable — available versions unknown"
			return emitInfoResult(cmd, format, pkgName, scope, installedVersion, installedGen,
				nil, "", note, nil, nil, nil, installedAtt)
		}
		return planExecError(fetchErr)
	}

	// Catalog may be nil when the scope has no packages in the profile.
	var available []string
	var sourceName string
	var newestCand *infoNewest
	var recommends, suggests []string

	if fr.Catalog != nil {
		available = fr.Catalog.Versions(pkgName)
		if len(available) == 0 {
			// Unknown name in catalog — use Newest to produce a typed ResolveError
			// that planerr translation can frame with the right hint.
			_, err := fr.Catalog.Newest(pkgName, "")
			if err != nil {
				if installedVersion == "" {
					return planExecError(err)
				}
				// installed but not in catalog — treat same as offline
				note := "source unreachable — available versions unknown"
				return emitInfoResult(cmd, format, pkgName, scope, installedVersion, installedGen,
					nil, "", note, nil, nil, nil, installedAtt)
			}
		}
		if cand, err := fr.Catalog.Newest(pkgName, ""); err == nil {
			newestCand = &infoNewest{artifact: cand.Artifact}
			sourceName = cand.Source
			recommends = relNames(cand.Recommends)
			suggests = relNames(cand.Suggests)
		}
	}

	return emitInfoResult(cmd, format, pkgName, scope, installedVersion, installedGen,
		available, sourceName, "", newestCand, recommends, suggests, installedAtt)
}

// emitListEmpty writes the no-packages-installed output and returns nil.
func emitListEmpty(cmd *cobra.Command, format Format) error {
	const msg = "no packages installed — run `polypkg install <name>` to get started"
	EmitResult(cmd, format, "list", map[string]any{
		"packages": []any{},
	}, func(w *bytes.Buffer, _ map[string]any) {
		fmt.Fprintln(w, msg)
	})
	return nil
}

// emitListResult writes the list of installed packages.
func emitListResult(
	cmd *cobra.Command,
	format Format,
	scope string,
	gen int,
	manifest *schema.Manifest,
	pins map[string]string, // name → version constraint (e.g. "=1.0.0") or ""
) error {
	entries := manifest.Entries
	sorted := make([]schema.ManifestEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	type pkgRow struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Scope   string `json:"scope"`
		Pinned  string `json:"pinned"`
	}
	rows := make([]pkgRow, 0, len(sorted))
	for i := range sorted {
		e := &sorted[i]
		pin := ""
		if c, ok := pins[e.Name]; ok && strings.HasPrefix(c, "=") {
			pin = c
		}
		rows = append(rows, pkgRow{Name: e.Name, Version: e.Version, Scope: scope, Pinned: pin})
	}

	// Build JSON-compatible data map.
	pkgList := make([]any, len(rows))
	for i, r := range rows {
		pkgList[i] = map[string]any{
			"name":    r.Name,
			"version": r.Version,
			"scope":   r.Scope,
			"pinned":  r.Pinned,
		}
	}

	EmitResult(cmd, format, "list", map[string]any{
		"packages":   pkgList,
		"generation": gen,
		"scope":      scope,
	}, func(w *bytes.Buffer, _ map[string]any) {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, r := range rows {
			if r.Pinned != "" {
				fmt.Fprintf(tw, "%s\t%s\t(pinned: %s)\n", r.Name, r.Version, r.Pinned)
			} else {
				fmt.Fprintf(tw, "%s\t%s\n", r.Name, r.Version)
			}
		}
		_ = tw.Flush()
	})
	return nil
}

// infoNewest carries the newest candidate's artifact name for text display.
type infoNewest struct {
	artifact string
}

// emitInfoResult writes the info output for a package and always returns nil.
// offlineNote is non-empty when available versions are unknown due to an offline
// source; it is printed as an inline note in text mode.
// newest is optional metadata about the newest available candidate.
// recommends and suggests are the weak relation lists from the newest catalog
// candidate; both may be nil when the catalog is unavailable.
// att is the installed entry's install-time attestation record (D11); nil when
// the package is not installed or its generation predates the v2 chain (the
// JSON field then serializes as null, like the other optional fields).
func emitInfoResult(
	cmd *cobra.Command,
	format Format,
	pkgName, scope string,
	installedVersion string,
	installedGen int,
	available []string,
	sourceName string,
	offlineNote string,
	newest *infoNewest,
	recommends []string,
	suggests []string,
	att *schema.AttestationState,
) error { //nolint:unparam // always nil; matches the error-propagation convention of runInfo's callers
	artifactStr := ""
	if newest != nil {
		artifactStr = newest.artifact
	}
	data := map[string]any{
		"name":        pkgName,
		"installed":   installedVersion,
		"generation":  installedGen,
		"available":   available,
		"source":      sourceName,
		"scope":       scope,
		"note":        offlineNote,
		"artifact":    artifactStr,
		"recommends":  recommends,
		"suggests":    suggests,
		"attestation": att,
	}
	EmitResult(cmd, format, "info", data, func(w *bytes.Buffer, _ map[string]any) {
		fmt.Fprintf(w, "%s\n", pkgName)
		if installedVersion != "" {
			fmt.Fprintf(w, "  installed: %s (generation %d)\n", installedVersion, installedGen)
		} else {
			fmt.Fprintf(w, "  installed: none\n")
		}
		if line := attestationLine(att); line != "" {
			fmt.Fprintf(w, "  attestation: %s\n", line)
		}
		if offlineNote != "" {
			fmt.Fprintf(w, "  note: %s\n", offlineNote)
		} else if len(available) > 0 {
			fmt.Fprintf(w, "  available: %s\n", strings.Join(available, ", "))
		}
		if artifactStr != "" && len(available) > 0 {
			fmt.Fprintf(w, "  artifact:  %s (newest)\n", artifactStr)
		}
		if sourceName != "" {
			fmt.Fprintf(w, "  source:    %s\n", sourceName)
		}
		if len(recommends) > 0 {
			fmt.Fprintf(w, "  recommends: %s\n", strings.Join(recommends, ", "))
		}
		if len(suggests) > 0 {
			fmt.Fprintf(w, "  suggests:  %s\n", strings.Join(suggests, ", "))
		}
	})
	return nil
}

// attestationLine renders the install-time attestation record for the info
// text output: "verified (<predicate URIs>) under policy <p>" for a verified
// record, "unattested (policy <p> at install)" for an unattested one, and ""
// when the record is absent (generation predates the v2 attestation chain).
func attestationLine(a *schema.AttestationState) string {
	switch {
	case a == nil:
		return ""
	case a.GateDisabled:
		return fmt.Sprintf("attestation gate disabled (tier: off, policy %s at install) — installed without require/posture enforcement", a.PolicyAtInstall)
	case a.Status == "verified":
		line := fmt.Sprintf("verified (%s) under policy %s",
			strings.Join(a.PredicateTypes, ", "), a.PolicyAtInstall)
		if b := carriedBindingSummary(a.CarriedBindings); b != "" {
			line += "; carried: " + b
		}
		return line
	case a.Status == "unattested":
		return fmt.Sprintf("unattested (policy %s at install)", a.PolicyAtInstall)
	default:
		return ""
	}
}

// carriedBindingSummary renders each carried binding as
// "<predicate> — <tier> [<identity>]", surfacing the tier so a reader
// distinguishes an anchored ref from a verified-transport-only one, and the
// verifying identity (builder id or Fulcio SAN) for anchored tiers that record
// one. Empty when there are no carried bindings.
func carriedBindingSummary(bindings []schema.CarriedBinding) string {
	if len(bindings) == 0 {
		return ""
	}
	parts := make([]string, 0, len(bindings))
	for i := range bindings {
		part := bindings[i].PredicateType + " — " + bindings[i].Tier
		if id := bindingIdentity(bindings[i]); id != "" {
			part += " [" + id + "]"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
}

// bindingIdentity returns the verifying identity recorded for an anchored
// carried binding: the SLSA builder id (falling back to the verifying key id)
// for builder-verified, or the Fulcio SAN for verified-offline. Returns "" for
// tiers that carry no identity (bound-unverified, verified-transport-only).
func bindingIdentity(b schema.CarriedBinding) string {
	switch b.Tier {
	case schema.CarriedTierBuilderVerified:
		if b.BuilderIdentity != "" {
			return b.BuilderIdentity
		}
		return b.VerifyingKeyID
	case schema.CarriedTierVerifiedOffline:
		return b.CertificateIdentity
	default:
		return ""
	}
}

// resolveListScope resolves --scope/--prefix and returns the scope, dataHome,
// and stateHome. p is the parsed profile (may be an empty *schema.Profile{}
// when no profile is available). For system scope the prefix is resolved via
// the same three-tier precedence as the write verbs: --prefix flag >
// POLYPKG_SYSTEM_PREFIX env > profile.scopes.system.prefix.
func resolveListScope(cmd *cobra.Command, p *schema.Profile) (scope, dataHome, stateHome string, err error) {
	scope, prefix, err := resolveScope(cmd, p)
	if err != nil {
		return "", "", "", err
	}
	dh, sh, err := scopeHomes(scope, prefix)
	if err != nil {
		return "", "", "", err
	}
	return scope, dh, sh, nil
}

// relNames extracts the Name field from each schema.Relation, returning a flat
// string slice. Returns nil for empty input; since the result is placed into
// the info result's map[string]any, an empty list serializes as JSON null
// (consistent with the command's other optional fields like note/artifact),
// not an omitted key.
func relNames(rels []schema.Relation) []string {
	if len(rels) == 0 {
		return nil
	}
	names := make([]string, len(rels))
	for i, r := range rels {
		names[i] = r.Name
	}
	return names
}

// readGenManifest opens and parses the manifest for generation gen under dataHome.
// dataHome is the resolved substrate data home (already includes the "polypkg" segment).
func readGenManifest(dataHome string, gen int) (*schema.Manifest, error) {
	mPath := filepath.Join(dataHome, "generations", strconv.Itoa(gen), "manifest.json")
	mf, err := os.Open(filepath.Clean(mPath))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &schema.Manifest{}, nil
		}
		return nil, err
	}
	defer func() { _ = mf.Close() }()
	return schema.ParseManifest(mf)
}

// bestEffortProfile tries to parse the current profile and returns it. On any
// error (missing profile, parse failure, etc.) it returns an empty
// *schema.Profile so callers can proceed without a profile. This is
// intentionally non-fatal: read-only verbs (list, info, search) degrade
// gracefully when no profile is configured.
func bestEffortProfile(cmd *cobra.Command) *schema.Profile {
	profilePath, err := resolveProfilePath(cmd, nil)
	if err != nil {
		return &schema.Profile{}
	}
	f, err := openProfileFile(cmd, profilePath)
	if err != nil {
		return &schema.Profile{}
	}
	defer func() { _ = f.Close() }()
	p, err := schema.ParseProfile(f, profilePath)
	if err != nil {
		return &schema.Profile{}
	}
	return p
}

// profilePins returns a map of package name → version constraint for packages
// with exact-pin constraints (starting with "=") in p for the given scope.
func profilePins(p *schema.Profile, scope string) map[string]string {
	pins := map[string]string{}
	for name, ref := range p.Packages[scope] {
		if strings.HasPrefix(ref.Version, "=") {
			pins[name] = ref.Version
		}
	}
	return pins
}
