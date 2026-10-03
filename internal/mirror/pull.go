package mirror

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/source"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// safePkgName is the legitimate package-name charset (package-v1.json). Index map
// keys are unconstrained, so a compromised-but-pinned upstream could name a package
// with YAML/path metacharacters; confining pulled names to this charset fails closed
// at the staging boundary (protects the staged path, artifact filename, and the
// generated manifest's YAML key position).
var safePkgName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// safePkgVersion is a semver-safe charset. The name@version exact-selection path does
// not re-validate the version through semver, so guard it here too.
var safePkgVersion = regexp.MustCompile(`^[a-zA-Z0-9.+-]+$`)

// PullOptions configures one pull from a single upstream polypkg source.
type PullOptions struct {
	URL               string   // upstream source URL (https:// or a local path / file://)
	TrustRoot         string   // path to the source's trust_root.pub anchor
	SourceType        string   // trust type; "" defaults to "polypkg-native"
	SourceName        string   // logical name (verifier context)
	AcceptExpiryUntil string   // optional 2e-1 freshness grace deadline (RFC3339)
	Selectors         []string // empty ⇒ latest of every package; "name" ⇒ latest of name; "name@version" ⇒ that one
	// AllVersions widens what an unpinned selection means, from "latest" to
	// "every published version": with no selectors, every version of every
	// package; with a bare "name" selector, every version of that name. An
	// explicit "name@version" selector still wins regardless of this flag —
	// it is already unambiguous.
	AllVersions bool
	StageDir    string // root under which staging/ is written
}

// PulledPackage records one verified (and, from Task 2, staged) package.
type PulledPackage struct {
	Name         string
	Version      string
	ContentHash  string // blake3: of the artifact (from the verified index)
	ArtifactPath string // staged .tar.zst (absolute) — set by Task 2
	AttDir       string // staged attestations dir (absolute) — set by Task 2
}

// PullResult reports a completed pull.
type PullResult struct {
	Packages        []PulledPackage
	TrustBundlePath string   // staged trust-bundle.json — set by Task 3
	Graced          []string // freshness-graced doc notes (surfaced loudly by callers)
	// Narrowed lists the packages for which this pull mirrored only the
	// latest upstream version even though the upstream published more than
	// one (an empty selector set or a bare "name" selector both resolve to
	// "latest"). Kept separate from Graced: that field is specifically about
	// freshness grace, and folding a completeness signal into a security
	// signal would muddy both.
	Narrowed []string
	// RevokedAttestations / RevokedBuilderKeys are the upstream's revoked sets as
	// loaded and verified during this pull (nil when the upstream published no
	// revocation list). Callers propagate their union into the mirror's own
	// revocations.json.
	RevokedAttestations []string
	RevokedBuilderKeys  []string
}

// PrebuiltManifestParams are the local re-publish settings for the generated
// manifest (used by WritePrebuiltManifest in Task 3).
type PrebuiltManifestParams struct {
	Source  string
	Output  string
	KeyPath string
	KeyKDF  string
}

// Pull fetches and verifies one upstream source's trust document and signed
// index, resolves the selection to one entry per package name, and (from Task 2)
// stages each verified artifact + its attestation blobs and (Task 3) the trust
// bundle. It reuses the trust crypto kernel (state.Verify); the digest re-binding
// is repo build's ingest job (2e-3a), not done here. No anti-rollback serial
// floor: a pull is a stateless one-shot fetch of current state for re-publish.
func Pull(ctx context.Context, opts PullOptions) (*PullResult, error) {
	if opts.SourceType == "" {
		opts.SourceType = "polypkg-native"
	}
	anchor, err := os.ReadFile(filepath.Clean(opts.TrustRoot)) //nolint:gosec // G304: operator-supplied trust anchor path
	if err != nil {
		return nil, fmt.Errorf("read trust root %q: %w", opts.TrustRoot, err)
	}
	verifier, err := trust.NewVerifier(opts.SourceType, string(anchor), opts.SourceName)
	if err != nil {
		return nil, fmt.Errorf("trust verifier: %w", err)
	}
	backend := source.NewNativeBackend(source.NativeBackendOpts{
		URL:      opts.URL,
		CacheDir: filepath.Join(opts.StageDir, ".cache"),
	})

	docBytes, docSig, err := backend.FetchTrustDoc(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch trust document: %w", err)
	}
	state, _, trustGraced, err := verifier.LoadTrust(docBytes, docSig, 0, opts.AcceptExpiryUntil)
	if err != nil {
		return nil, fmt.Errorf("verify trust document: %w", err)
	}
	var graced []string
	if trustGraced {
		graced = append(graced, "trust document (grace until "+opts.AcceptExpiryUntil+")")
	}

	rawIndex, idxSig, err := backend.FetchIndex(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch index: %w", err)
	}
	if _, err := state.Verify(trust.RoleIndex, rawIndex, idxSig); err != nil {
		return nil, fmt.Errorf("index signature verification failed: %w", err)
	}
	index, err := schema.ParseIndex(bytes.NewReader(rawIndex))
	if err != nil {
		return nil, fmt.Errorf("parse index: %w", err)
	}
	idxGraced, err := trust.CheckExpiry("index", index.Expires, opts.AcceptExpiryUntil)
	if err != nil {
		return nil, err
	}
	if idxGraced {
		graced = append(graced, "index (grace until "+opts.AcceptExpiryUntil+")")
	}

	// Optional revocation list — fetched and enforced so the pull cannot LAUNDER
	// an upstream revocation (repo build does not carry revocations forward, and
	// the consumer treats revocation as absolute). Absent ⇒ nothing revoked.
	var revocations *trust.Revocations
	rDoc, rSig, rerr := backend.FetchRevocationList(ctx)
	switch {
	case rerr == nil:
		var rGraced bool
		revocations, _, rGraced, _, err = verifier.LoadRevocationList(rDoc, rSig, 0, opts.AcceptExpiryUntil)
		if err != nil {
			return nil, fmt.Errorf("verify revocation list: %w", err)
		}
		if rGraced {
			graced = append(graced, "revocation list (grace until "+opts.AcceptExpiryUntil+")")
		}
	case errors.Is(rerr, source.ErrMetadataAbsent):
		// no revocation list published ⇒ nothing revoked
	default:
		return nil, fmt.Errorf("fetch revocation list: %w", rerr)
	}

	selected, narrowed, err := resolvePullSelection(index, opts.Selectors, opts.AllVersions)
	if err != nil {
		return nil, err
	}
	stagingRoot := filepath.Join(opts.StageDir, "staging")
	res := &PullResult{
		Graced:              graced,
		Narrowed:            narrowed,
		RevokedAttestations: revocations.RevokedAttestationHashes(),
		RevokedBuilderKeys:  revocations.RevokedBuilderKeyIDs(),
	}
	for i := range selected {
		sel := &selected[i]
		data, err := backend.Fetch(ctx, sel.entry.Artifact)
		if err != nil {
			return nil, fmt.Errorf("fetch artifact %s-%s: %w", sel.name, sel.version, err)
		}
		sig, err := backend.FetchSignature(ctx, sel.entry.Artifact)
		if err != nil {
			return nil, fmt.Errorf("fetch artifact signature %s-%s: %w", sel.name, sel.version, err)
		}
		if err := verifyClaim(state, trust.RoleArtifact, data, sig, sel.name, sel.version, sel.entry.ContentHash); err != nil {
			return nil, err
		}
		pkgDir, err := stagedPkgDir(stagingRoot, sel.name, sel.version)
		if err != nil {
			return nil, err
		}
		attDir := filepath.Join(pkgDir, "attestations")
		if err := os.MkdirAll(attDir, 0o755); err != nil { //nolint:gosec // G301: operator-local staging dir
			return nil, fmt.Errorf("create staging dir for %s-%s: %w", sel.name, sel.version, err)
		}
		artPath := filepath.Join(pkgDir, sel.name+".tar.zst")
		if err := os.WriteFile(artPath, data, 0o644); err != nil { //nolint:gosec // G306: operator-local staging file
			return nil, fmt.Errorf("stage artifact %s-%s: %w", sel.name, sel.version, err)
		}
		for j := range sel.entry.Attestations {
			ref := &sel.entry.Attestations[j]
			if revocations != nil && revocations.IsAttestationRevoked(ref.ContentHash) {
				return nil, fmt.Errorf("refusing to pull %s-%s: attestation %s is revoked by the upstream revocation list", sel.name, sel.version, ref.ContentHash)
			}
			attData, err := backend.Fetch(ctx, ref.Artifact)
			if err != nil {
				return nil, fmt.Errorf("fetch attestation %s: %w", ref.Artifact, err)
			}
			attSig, err := backend.FetchSignature(ctx, ref.Artifact)
			if err != nil {
				return nil, fmt.Errorf("fetch attestation signature %s: %w", ref.Artifact, err)
			}
			if err := verifyClaim(state, trust.RoleAttestation, attData, attSig, sel.name, sel.version, ref.ContentHash); err != nil {
				return nil, err
			}
			blobName := strings.TrimPrefix(ref.ContentHash, "blake3:") + ".att.json"
			if err := os.WriteFile(filepath.Join(attDir, blobName), attData, 0o644); err != nil { //nolint:gosec // G306: operator-local staging file
				return nil, fmt.Errorf("stage attestation %s: %w", ref.Artifact, err)
			}
		}
		res.Packages = append(res.Packages, PulledPackage{
			Name: sel.name, Version: sel.version, ContentHash: sel.entry.ContentHash,
			ArtifactPath: artPath, AttDir: attDir,
		})
	}

	// Optional upstream trust bundle → stage verbatim (verified) for carry-forward
	// by `repo build` (2e-3a). Absent ⇒ nothing to carry.
	bDoc, bSig, berr := backend.FetchTrustBundle(ctx)
	switch {
	case berr == nil:
		if _, _, bGraced, verr := verifier.LoadBundle(bDoc, bSig, 0, opts.AcceptExpiryUntil); verr != nil {
			return nil, fmt.Errorf("verify trust bundle: %w", verr)
		} else if bGraced {
			res.Graced = append(res.Graced, "trust bundle (grace until "+opts.AcceptExpiryUntil+")")
		}
		if revocations != nil {
			// Re-parse the signature-verified bytes to iterate builder keys (Bundle
			// exposes them only by lookup). Refuse carrying a revoked key forward —
			// carry-forward would otherwise launder the upstream's revocation.
			tb, perr := schema.ParseTrustBundle(bytes.NewReader(bDoc))
			if perr != nil {
				return nil, fmt.Errorf("parse verified trust bundle: %w", perr)
			}
			for i := range tb.BuilderKeys {
				if revocations.IsBuilderKeyRevoked(tb.BuilderKeys[i].KeyID) {
					return nil, fmt.Errorf("refusing to carry trust bundle forward: builder key %q is revoked by the upstream revocation list", tb.BuilderKeys[i].KeyID)
				}
			}
		}
		if err := os.MkdirAll(stagingRoot, 0o755); err != nil { //nolint:gosec // G301: operator-local staging dir
			return nil, fmt.Errorf("create staging dir: %w", err)
		}
		tbPath := filepath.Join(stagingRoot, "trust-bundle.json")
		if err := os.WriteFile(tbPath, bDoc, 0o644); err != nil { //nolint:gosec // G306: operator-local staging file
			return nil, fmt.Errorf("stage trust bundle: %w", err)
		}
		res.TrustBundlePath = tbPath
	case errors.Is(berr, source.ErrMetadataAbsent):
		// no bundle → nothing to carry forward
	default:
		return nil, fmt.Errorf("fetch trust bundle: %w", berr)
	}
	return res, nil
}

// WritePrebuiltManifest writes a `repo build`-ready manifest for a single pull.
// It delegates to WritePrebuiltManifestMulti so single- and multi-source pulls
// share one emitter.
func WritePrebuiltManifest(manifestPath string, p PrebuiltManifestParams, res *PullResult) error {
	return WritePrebuiltManifestMulti(manifestPath, p, []*PullResult{res})
}

// WritePrebuiltManifestMulti writes a `repo build`-ready polypkg.repo/v1 manifest
// whose packages are the prebuilt entries from every PullResult (one per upstream
// source). Each package references ITS OWN source's staged trust bundle, so
// `repo build` ingest (mergeCarriedBundle) folds the per-source builder keys
// together (dedup by key_id; a conflicting key_id fails closed). Several
// versions of the same package name from ONE source are grouped under a single
// "name:" YAML key with one "- prebuilt:" list item per version. Refuses two
// DIFFERENT sources that both stage the same package name — a repo manifest
// keys packages by name, so a cross-source collision is ambiguous and fails
// closed. Paths are written as-is from PullResult (absolute), so the manifest
// is buildable from any cwd.
func WritePrebuiltManifestMulti(manifestPath string, p PrebuiltManifestParams, results []*PullResult) error {
	var sb strings.Builder
	sb.WriteString("schema: polypkg.repo/v1\n")
	sb.WriteString("source: " + p.Source + "\n")
	sb.WriteString("output: " + p.Output + "\n")
	sb.WriteString("key:\n  path: " + p.KeyPath + "\n  kdf: " + p.KeyKDF + "\n")
	sb.WriteString("packages:\n")
	// claimedBy tracks which results-slice index (source) first staged a given
	// package name, so two versions of one name from the SAME source group
	// together while two DIFFERENT sources staging the same name still collide.
	claimedBy := map[string]int{}
	for ri, res := range results {
		order := make([]string, 0, len(res.Packages))
		byName := map[string][]*PulledPackage{}
		for i := range res.Packages {
			pk := &res.Packages[i]
			if prev, ok := claimedBy[pk.Name]; ok && prev != ri {
				return fmt.Errorf("package %q pulled from more than one source (a repo manifest keys packages by name)", pk.Name)
			}
			claimedBy[pk.Name] = ri
			if _, ok := byName[pk.Name]; !ok {
				order = append(order, pk.Name)
			}
			byName[pk.Name] = append(byName[pk.Name], pk)
		}
		for _, name := range order {
			sb.WriteString("  " + name + ":\n")
			for _, pk := range byName[name] {
				sb.WriteString("    - prebuilt:\n")
				sb.WriteString("        artifact: " + pk.ArtifactPath + "\n")
				sb.WriteString("        attestations: " + pk.AttDir + "\n")
				if res.TrustBundlePath != "" {
					sb.WriteString("        trust_bundle: " + res.TrustBundlePath + "\n")
				}
			}
		}
	}
	if err := os.WriteFile(manifestPath, []byte(sb.String()), 0o644); err != nil { //nolint:gosec // G306: operator-local manifest
		return fmt.Errorf("write prebuilt manifest: %w", err)
	}
	return nil
}

// ManagementManifestName is the file WriteManagementManifest emits inside the
// mirror's output directory. It is the default --manifest of every `repo`
// subcommand, so an operator standing in the mirror can run them with no flags.
const ManagementManifestName = "polypkg-repo.yaml"

// WriteManagementManifest writes <outputDir>/polypkg-repo.yaml describing the
// mirror that was just published, so `repo revoke`, `repo status`, `repo build`,
// `repo key show`, and `repo export-bundle` all work against it.
//
// The build manifest a pull generates lives in the staging root and references
// staged artifacts, and the staging root is a temp dir the pull deletes; a copy
// of it would be dead on arrival. This manifest instead points each package at
// the mirror's OWN published pool blob, whose bytes are byte-identical to what
// was staged. `repo build` therefore cache-hits every package and is a true
// no-op, and `repo status` reports the mirror up to date rather than failing on
// a vanished staging path.
//
// Every path is written absolute so the manifest resolves from any working
// directory (`repo build` resolves relative paths against the manifest's own
// directory, which would silently retarget them at the published tree).
//
// Caveat, recorded in the emitted file: prebuilt.attestations points at the
// shared pool directory rather than a per-package one. Nothing reads it while
// the build cache holds an entry for the package. If the cache is lost AND the
// mirror carries more than one package, ingest will try to bind another
// package's attestation and refuse — loudly, never silently dropping provenance.
// The fix in that case is to re-run `mirror pull`, which is the mirror's normal
// refresh path anyway.
func WriteManagementManifest(p PrebuiltManifestParams) error {
	absOut, err := filepath.Abs(p.Output)
	if err != nil {
		return fmt.Errorf("resolve mirror output dir: %w", err)
	}
	absKey, err := filepath.Abs(p.KeyPath)
	if err != nil {
		return fmt.Errorf("resolve mirror signing key path: %w", err)
	}
	idxRaw, err := os.ReadFile(filepath.Join(absOut, "index.json")) //nolint:gosec // G304: the index this pull just published
	if err != nil {
		return fmt.Errorf("read published index for the mirror manifest: %w", err)
	}
	idx, err := schema.ParseIndex(bytes.NewReader(idxRaw))
	if err != nil {
		return fmt.Errorf("parse published index for the mirror manifest: %w", err)
	}

	names := make([]string, 0, len(idx.Packages))
	for name := range idx.Packages {
		names = append(names, name)
	}
	sort.Strings(names)

	// The carried builder keys and sigstore roots the pull folded forward live in
	// the published trust-bundle.json. Re-declaring it on every package keeps a
	// rebuild's merge (dedup by key_id, identical material) idempotent, so the
	// bundle survives instead of being dropped and the serial bumped.
	trustBundle := filepath.Join(absOut, "trust-bundle.json")
	if _, statErr := os.Stat(trustBundle); statErr != nil {
		trustBundle = ""
	}
	poolDir := filepath.Join(absOut, "pool")

	var sb strings.Builder
	sb.WriteString("# Generated by `polypkg mirror pull`. Re-run that command to refresh the\n")
	sb.WriteString("# mirror; this manifest exists so `polypkg repo revoke`, `repo status`,\n")
	sb.WriteString("# `repo key show`, and `repo export-bundle` can be run against the mirror.\n")
	sb.WriteString("# Each package points at this mirror's own published pool blob, so a\n")
	sb.WriteString("# `repo build` here is a no-op while the build cache in key-dir is intact.\n")
	sb.WriteString("schema: polypkg.repo/v1\n")
	sb.WriteString("source: " + p.Source + "\n")
	sb.WriteString("output: " + absOut + "\n")
	sb.WriteString("key:\n  path: " + absKey + "\n  kdf: " + p.KeyKDF + "\n")
	sb.WriteString("packages:\n")
	for _, name := range names {
		entries := idx.Packages[name]
		sb.WriteString("  " + name + ":\n")
		for i := range entries {
			sb.WriteString("    - prebuilt:\n")
			sb.WriteString("        artifact: " + filepath.Join(absOut, filepath.FromSlash(entries[i].Artifact)) + "\n")
			sb.WriteString("        attestations: " + poolDir + "\n")
			if trustBundle != "" {
				sb.WriteString("        trust_bundle: " + trustBundle + "\n")
			}
		}
	}

	path := filepath.Join(absOut, ManagementManifestName)
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil { //nolint:gosec // G306: published alongside the mirror's own signed documents
		return fmt.Errorf("write mirror manifest: %w", err)
	}
	return nil
}

// stagedPkgDir returns the staging dir for a package, refusing any name/version
// that could escape stagingRoot via path traversal. Package names are index map
// keys with no schema charset constraint (index-v2.json), so a compromised source
// could publish a signature-valid index naming a package "../../evil"; this guard
// confines the pull's writes regardless (defense in depth; mirrors verify.go's
// readTar traversal rejection).
//
// The layout is <name>/<version> (two path segments), NOT <name>-<version>: a
// single delimiter join is ambiguous — ("a","b-1.0.0") and ("a-b","1.0.0") would
// both collapse to "a-b-1.0.0", letting a compromised upstream merge two packages
// into one attestations/ dir (cross-binding at ingest). The charset guards
// (safePkgName/safePkgVersion) plus the traversal check guarantee neither name nor
// version contains "/" or "..", so each is exactly one safe segment and distinct
// (name,version) pairs can never collide.
func stagedPkgDir(stagingRoot, name, version string) (string, error) {
	for _, s := range []string{name, version} {
		if s == "" || s == "." || s == ".." || strings.ContainsAny(s, `/\`) || strings.Contains(s, "..") {
			return "", fmt.Errorf("refusing unsafe package name/version %q (path traversal)", s)
		}
	}
	if !safePkgName.MatchString(name) {
		return "", fmt.Errorf("refusing package name %q: not a valid package name (must match [A-Za-z0-9_-]+)", name)
	}
	if !safePkgVersion.MatchString(version) {
		return "", fmt.Errorf("refusing package version %q: contains unsafe characters", version)
	}
	dir := filepath.Join(stagingRoot, name, version)
	rootClean := filepath.Clean(stagingRoot)
	if dir != rootClean && !strings.HasPrefix(dir, rootClean+string(filepath.Separator)) {
		return "", fmt.Errorf("refusing package %q-%q: staging path escapes %q", name, version, stagingRoot)
	}
	return dir, nil
}

// verifyClaim checks a fetched blob against the source keyring under `role` and
// asserts its signed claim (name/version/hash) matches the expected index entry.
// The crypto is the SHARED trust kernel (state.Verify); this re-states only the
// small "claim matches the index" assertion (mirrors planner.verifyArtifact).
// (Used by Task 2; defined now so the seam is fixed.)
func verifyClaim(state trust.Keyring, role trust.Role, data []byte, sig, name, version, wantHash string) error {
	claims, err := state.Verify(role, data, sig)
	if err != nil {
		return fmt.Errorf("signature verification failed for %s-%s: %w", name, version, err)
	}
	cname, cversion, chash, err := claims.Artifact()
	if err != nil {
		return fmt.Errorf("%s-%s: %w", name, version, err)
	}
	if got := contentHash(data); got != wantHash {
		return fmt.Errorf("hash mismatch for %s-%s: index %s, actual %s", name, version, wantHash, got)
	}
	if cname != name || cversion != version || chash != wantHash {
		return fmt.Errorf("signed claim %s-%s/%s does not match index %s-%s/%s", cname, cversion, chash, name, version, wantHash)
	}
	return nil
}

type pullSelection struct {
	name    string
	version string
	entry   schema.IndexEntry
}

// resolvePullSelection resolves selectors against the verified index: empty ⇒
// latest of every package; "name" ⇒ latest of that name; "name@version" ⇒ that
// exact version. A repo manifest now holds a list of versions per name, so
// selecting two distinct versions of the same name (e.g. "hello@1.0.0" and
// "hello@1.1.0") is coherent and resolves to two selections. What is still
// refused is a genuine conflict: the same selector repeated, or a bare name
// paired with an explicit version of that name (the bare form means "latest",
// so pairing it with a pin is ambiguous about which resolution the operator
// wants).
//
// It also returns narrowing notes: whenever a "latest" resolution (empty
// selectors, or a bare "name" selector) picks a winner from an upstream name
// that published more than one version, the older versions silently would
// not be mirrored. An explicit "name@version" selector never produces a
// note — the operator chose that outcome. Neither does an unpinned name
// under allVersions — nothing was dropped, so there is nothing to report.
//
// allVersions widens what an unpinned selection (empty selectors, or a bare
// "name") means, from "latest" to "every published version". It does not
// touch an explicit "name@version" selector: that is already unambiguous,
// so it is honoured as written regardless of allVersions.
func resolvePullSelection(index *schema.Index, selectors []string, allVersions bool) ([]pullSelection, []string, error) {
	pick := func(name string) (pullSelection, error) {
		entries, ok := index.Packages[name]
		if !ok || len(entries) == 0 {
			return pullSelection{}, fmt.Errorf("package %q not found in the upstream index", name)
		}
		best := 0
		bv, err := semver.NewVersion(entries[0].Version)
		if err != nil {
			return pullSelection{}, fmt.Errorf("package %q version %q is not semver", name, entries[0].Version)
		}
		for i := 1; i < len(entries); i++ {
			v, verr := semver.NewVersion(entries[i].Version)
			if verr != nil {
				return pullSelection{}, fmt.Errorf("package %q version %q is not semver", name, entries[i].Version)
			}
			if v.GreaterThan(bv) {
				best, bv = i, v
			}
		}
		return pullSelection{name: name, version: entries[best].Version, entry: entries[best]}, nil
	}
	// pickAll is pick's sibling for the --all-versions path: it returns every
	// entry for name instead of the single newest one, so it cannot share
	// pick's return shape. Order is fixed newest-first (matching pick's own
	// preference) rather than left as map/index order, because the emitted
	// manifest must be byte-stable across runs; the resolver only needs the
	// set, so this ordering exists for a human reading index.json.
	pickAll := func(name string) ([]pullSelection, error) {
		entries, ok := index.Packages[name]
		if !ok || len(entries) == 0 {
			return nil, fmt.Errorf("package %q not found in the upstream index", name)
		}
		versions := make([]*semver.Version, len(entries))
		for i := range entries {
			v, err := semver.NewVersion(entries[i].Version)
			if err != nil {
				return nil, fmt.Errorf("package %q version %q is not semver", name, entries[i].Version)
			}
			versions[i] = v
		}
		order := make([]int, len(entries))
		for i := range order {
			order[i] = i
		}
		sort.Slice(order, func(i, j int) bool { return versions[order[i]].GreaterThan(versions[order[j]]) })
		out := make([]pullSelection, len(entries))
		for i, idx := range order {
			out[i] = pullSelection{name: name, version: entries[idx].Version, entry: entries[idx]}
		}
		return out, nil
	}
	if len(selectors) == 0 {
		var out []pullSelection
		var notes []string
		for name := range index.Packages {
			if allVersions {
				sels, err := pickAll(name)
				if err != nil {
					return nil, nil, err
				}
				out = append(out, sels...)
				continue
			}
			sel, err := pick(name)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, sel)
			if note := narrowingNote(name, index.Packages[name], sel.version); note != "" {
				notes = append(notes, note)
			}
		}
		// Stable: preserves pickAll's newest-first order within a name across
		// the by-name sort (which only orders distinct names).
		sort.SliceStable(out, func(i, j int) bool { return out[i].name < out[j].name })
		sort.Strings(notes)
		return out, notes, nil
	}
	seenSelector := map[string]bool{}      // exact selector string, catches an outright repeat
	seenBareName := map[string]bool{}      // name selected bare (⇒ latest)
	seenVersionedName := map[string]bool{} // name selected with an explicit version
	var out []pullSelection
	var notes []string
	for _, s := range selectors {
		name, ver, hasVer := strings.Cut(s, "@")
		if seenSelector[s] {
			return nil, nil, fmt.Errorf("selector %q given more than once", s)
		}
		seenSelector[s] = true
		if hasVer && seenBareName[name] || !hasVer && seenVersionedName[name] {
			return nil, nil, fmt.Errorf(
				"package %q selected both bare and by explicit version: ambiguous, because a bare name means \"latest\" (pick one form)",
				name)
		}
		if hasVer {
			seenVersionedName[name] = true
		} else {
			seenBareName[name] = true
		}
		if !hasVer {
			if allVersions {
				sels, err := pickAll(name)
				if err != nil {
					return nil, nil, err
				}
				out = append(out, sels...)
				continue
			}
			sel, err := pick(name)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, sel)
			if note := narrowingNote(name, index.Packages[name], sel.version); note != "" {
				notes = append(notes, note)
			}
			continue
		}
		entries := index.Packages[name]
		found := false
		for i := range entries {
			if entries[i].Version == ver {
				out = append(out, pullSelection{name: name, version: ver, entry: entries[i]})
				found = true
				break
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("package %q version %q not found in the upstream index", name, ver)
		}
	}
	return out, notes, nil
}

// narrowingNote returns an actionable note when a "latest" resolution for
// name picked a winner (picked) out of an upstream entries list that
// published more than one version, naming exactly what this pull did not
// mirror and how to get it. Returns "" when there is nothing to report (the
// upstream published only one version of name).
func narrowingNote(name string, entries []schema.IndexEntry, picked string) string {
	if len(entries) <= 1 {
		return ""
	}
	var skipped []string
	for i := range entries {
		if entries[i].Version != picked {
			skipped = append(skipped, entries[i].Version)
		}
	}
	sort.Strings(skipped)
	if len(skipped) == 1 {
		return fmt.Sprintf("%s: mirrored %s, did not mirror %s (select it with --package %s@%s)",
			name, picked, skipped[0], name, skipped[0])
	}
	return fmt.Sprintf("%s: mirrored %s, did not mirror %s (select each with --package %s@<version>)",
		name, picked, strings.Join(skipped, ", "), name)
}
