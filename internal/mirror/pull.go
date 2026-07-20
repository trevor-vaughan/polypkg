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
	StageDir          string   // root under which staging/ is written
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
		revocations, _, rGraced, err = verifier.LoadRevocationList(rDoc, rSig, 0, opts.AcceptExpiryUntil)
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

	selected, err := resolvePullSelection(index, opts.Selectors)
	if err != nil {
		return nil, err
	}
	stagingRoot := filepath.Join(opts.StageDir, "staging")
	res := &PullResult{Graced: graced}
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
// together (dedup by key_id; a conflicting key_id fails closed). Refuses two
// sources that stage the same package name — a repo manifest keys packages by
// name, so a cross-source collision is ambiguous and fails closed. Paths are
// written as-is from PullResult (absolute), so the manifest is buildable from any
// cwd.
func WritePrebuiltManifestMulti(manifestPath string, p PrebuiltManifestParams, results []*PullResult) error {
	var sb strings.Builder
	sb.WriteString("schema: polypkg.repo/v1\n")
	sb.WriteString("source: " + p.Source + "\n")
	sb.WriteString("output: " + p.Output + "\n")
	sb.WriteString("key:\n  path: " + p.KeyPath + "\n  kdf: " + p.KeyKDF + "\n")
	sb.WriteString("packages:\n")
	seen := map[string]bool{}
	for _, res := range results {
		for i := range res.Packages {
			pk := &res.Packages[i]
			if seen[pk.Name] {
				return fmt.Errorf("package %q pulled from more than one source (a repo manifest keys packages by name)", pk.Name)
			}
			seen[pk.Name] = true
			sb.WriteString("  " + pk.Name + ":\n    prebuilt:\n")
			sb.WriteString("      artifact: " + pk.ArtifactPath + "\n")
			sb.WriteString("      attestations: " + pk.AttDir + "\n")
			if res.TrustBundlePath != "" {
				sb.WriteString("      trust_bundle: " + res.TrustBundlePath + "\n")
			}
		}
	}
	if err := os.WriteFile(manifestPath, []byte(sb.String()), 0o644); err != nil { //nolint:gosec // G306: operator-local manifest
		return fmt.Errorf("write prebuilt manifest: %w", err)
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

// resolvePullSelection resolves selectors against the verified index to ONE entry
// per package name (§10.11 D-2e3b-4): empty ⇒ latest of every package; "name" ⇒
// latest of that name; "name@version" ⇒ that exact version. Refuses selecting the
// same name twice (a repo manifest keys packages by name).
func resolvePullSelection(index *schema.Index, selectors []string) ([]pullSelection, error) {
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
	if len(selectors) == 0 {
		var out []pullSelection
		for name := range index.Packages {
			sel, err := pick(name)
			if err != nil {
				return nil, err
			}
			out = append(out, sel)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
		return out, nil
	}
	seen := map[string]bool{}
	var out []pullSelection
	for _, s := range selectors {
		name, ver, hasVer := strings.Cut(s, "@")
		if seen[name] {
			return nil, fmt.Errorf("package %q selected more than once (one version per name)", name)
		}
		seen[name] = true
		if !hasVer {
			sel, err := pick(name)
			if err != nil {
				return nil, err
			}
			out = append(out, sel)
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
			return nil, fmt.Errorf("package %q version %q not found in the upstream index", name, ver)
		}
	}
	return out, nil
}
