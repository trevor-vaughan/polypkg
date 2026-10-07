package mirror

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/jedisct1/go-minisign"

	"github.com/trevor-vaughan/polypkg/internal/platform"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/source"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

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
	// StateHome holds this mirror's per-upstream anti-rollback floors
	// (<StateHome>/trust/<PullResult.SeenKey>.json, the trust.Seen format the
	// consumer uses). Required: an empty value is refused rather than pulling
	// without floors.
	StateHome string
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
	// SeenKey names this upstream's anti-rollback record under
	// PullOptions.StateHome: "<SourceName>.<hex trust-root key id>". Keying on
	// the pinned anchor as well as the name stops two upstreams that sign under
	// the same source name from sharing, and wedging, one floor.
	SeenKey string
	// Seen holds the serials this pull verified, each at or above the stored
	// floor. Pull does not persist them. The caller stores them with
	// trust.StoreSeen(StateHome, SeenKey, Seen) only after the whole mirror run
	// has succeeded, so a run that fails later never ratchets a floor past what
	// the mirror actually published.
	Seen trust.Seen
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
// index, resolves the selection to one entry per package name, and stages each
// verified artifact, its attestation blobs, and the trust bundle. It reuses the
// trust crypto kernel (state.Verify). The digest re-binding is repo build's
// ingest job (2e-3a), not done here.
//
// Anti-rollback: the mirror re-signs what it pulls, so its clients can only be
// as current as the mirror. Pull therefore enforces the upstream's serial
// floors persisted under opts.StateHome (the consumer's trust.Seen format) for
// all four signed documents. It also refuses a trust bundle or revocation list
// that has vanished after one was seen. Pull only reads the floors. The
// advanced serials come back in PullResult.Seen for the caller to persist.
// When a sources file lists one upstream more than once, each entry's Pull
// loads the same pre-run floor; StoreFloors merges what they verified.
//
// Every error Pull returns is an *UpstreamError naming the upstream.
func Pull(ctx context.Context, opts PullOptions) (*PullResult, error) {
	res, seenKey, err := pull(ctx, opts)
	if err == nil {
		return res, nil
	}
	ue := &UpstreamError{SourceName: opts.SourceName, URL: source.RedactURL(opts.URL), Err: err}
	var rb *trust.RollbackError
	var se *StrippedError
	var fe *FloorStateError
	if seenKey != "" && (errors.As(err, &rb) || errors.As(err, &se) || errors.As(err, &fe)) {
		ue.FloorRecord = trust.SeenPath(opts.StateHome, seenKey)
	}
	return nil, ue
}

// UpstreamError is every error Pull returns. A mirror pull may name several
// upstreams, so the error says which one failed, by name and by URL (with any
// credentials redacted).
type UpstreamError struct {
	SourceName string
	URL        string // redacted
	// FloorRecord is the path of this upstream's anti-rollback record when the
	// refusal comes from it: a rollback, a stripped trust bundle or revocation
	// list, or a record that cannot be read. Empty for any other failure.
	FloorRecord string
	Err         error
}

func (e *UpstreamError) Error() string {
	return fmt.Sprintf("upstream %q (%s): %v", e.SourceName, e.URL, e.Err)
}

func (e *UpstreamError) Unwrap() error { return e.Err }

// StrippedError is an optional signed document (trust bundle or revocation
// list) the upstream no longer serves although this mirror has recorded one.
type StrippedError struct {
	Document string // "trust bundle" or "revocation list"
	LastSeen uint64 // the serial recorded for it
}

func (e *StrippedError) Error() string {
	return fmt.Sprintf("%s absent but upstream previously published serial %d (rollback)", e.Document, e.LastSeen)
}

// FloorStateError is an anti-rollback record that exists but cannot be read
// or parsed. Pull refuses rather than treat it as a first pull.
type FloorStateError struct {
	Path string
	Err  error
}

func (e *FloorStateError) Error() string {
	return fmt.Sprintf("load anti-rollback state %s: %v", e.Path, e.Err)
}

func (e *FloorStateError) Unwrap() error { return e.Err }

// pull is Pull's body. It also returns the upstream's state key once known
// (before any document is verified), so Pull can name the record on a floor
// refusal.
func pull(ctx context.Context, opts PullOptions) (*PullResult, string, error) {
	var seenKey string
	if opts.SourceType == "" {
		opts.SourceType = "polypkg-native"
	}
	if opts.StateHome == "" {
		return nil, seenKey, errors.New("mirror pull needs a state directory for the upstream anti-rollback floors")
	}
	// The source name becomes a state file name, so confine it to the slug
	// charset before it reaches the filesystem. The upstream's signed documents
	// must carry this same name, so a legitimate upstream always passes.
	if err := schema.ValidateSourceName(opts.SourceName); err != nil {
		return nil, seenKey, fmt.Errorf("upstream source name: %w", err)
	}
	anchor, err := os.ReadFile(filepath.Clean(opts.TrustRoot)) //nolint:gosec // G304: operator-supplied trust anchor path
	if err != nil {
		return nil, seenKey, fmt.Errorf("read trust root %q: %w", opts.TrustRoot, err)
	}
	verifier, err := trust.NewVerifier(opts.SourceType, string(anchor), opts.SourceName)
	if err != nil {
		return nil, seenKey, fmt.Errorf("trust verifier: %w", err)
	}
	anchorKey, err := minisign.DecodePublicKey(string(anchor))
	if err != nil {
		return nil, seenKey, fmt.Errorf("decode trust root %q: %w", opts.TrustRoot, err)
	}
	seenKey = opts.SourceName + "." + hex.EncodeToString(anchorKey.KeyId[:])
	// A state file that exists but cannot be read or parsed fails closed.
	// Treating it as a first pull would reset every floor to zero and accept
	// exactly the replayed documents the floors exist to refuse.
	seen, err := trust.LoadSeen(opts.StateHome, seenKey)
	if err != nil {
		return nil, seenKey, &FloorStateError{Path: trust.SeenPath(opts.StateHome, seenKey), Err: err}
	}
	backend := source.NewNativeBackend(source.NativeBackendOpts{
		URL:      opts.URL,
		CacheDir: filepath.Join(opts.StageDir, ".cache"),
	})

	docBytes, docSig, err := backend.FetchTrustDoc(ctx)
	if err != nil {
		return nil, seenKey, fmt.Errorf("fetch trust document: %w", err)
	}
	state, trustSerial, trustGraced, err := verifier.LoadTrust(docBytes, docSig, seen.TrustSerial, opts.AcceptExpiryUntil)
	if err != nil {
		return nil, seenKey, fmt.Errorf("verify trust document: %w", err)
	}
	var graced []string
	if trustGraced {
		graced = append(graced, "trust document (grace until "+opts.AcceptExpiryUntil+")")
	}

	rawIndex, idxSig, err := backend.FetchIndex(ctx)
	if err != nil {
		return nil, seenKey, fmt.Errorf("fetch index: %w", err)
	}
	idxClaims, err := state.Verify(trust.RoleIndex, rawIndex, idxSig)
	if err != nil {
		return nil, seenKey, fmt.Errorf("index signature verification failed: %w", err)
	}
	indexSerial, err := idxClaims.IndexSerial()
	if err != nil {
		return nil, seenKey, fmt.Errorf("index: %w", err)
	}
	if indexSerial < seen.IndexSerial {
		return nil, seenKey, &trust.RollbackError{Document: "index", Serial: indexSerial, LastSeen: seen.IndexSerial}
	}
	index, err := schema.ParseIndex(bytes.NewReader(rawIndex))
	if err != nil {
		return nil, seenKey, fmt.Errorf("parse index: %w", err)
	}
	idxGraced, err := trust.CheckExpiry("index", index.Expires, opts.AcceptExpiryUntil)
	if err != nil {
		return nil, seenKey, err
	}
	if idxGraced {
		graced = append(graced, "index (grace until "+opts.AcceptExpiryUntil+")")
	}

	// Optional revocation list. It is fetched and enforced so the pull cannot
	// LAUNDER an upstream revocation (repo build does not carry revocations
	// forward, and the consumer treats revocation as absolute). Absent and never
	// seen means nothing is revoked. Absent after one was seen is a strip, and
	// is refused.
	revSerial := seen.RevocationSerial
	var revocations *trust.Revocations
	rDoc, rSig, rerr := backend.FetchRevocationList(ctx)
	switch {
	case rerr == nil:
		var rGraced bool
		revocations, revSerial, rGraced, _, err = verifier.LoadRevocationList(rDoc, rSig, seen.RevocationSerial, opts.AcceptExpiryUntil)
		if err != nil {
			return nil, seenKey, fmt.Errorf("verify revocation list: %w", err)
		}
		if rGraced {
			graced = append(graced, "revocation list (grace until "+opts.AcceptExpiryUntil+")")
		}
	case errors.Is(rerr, source.ErrMetadataAbsent):
		// serial 0 is schema-forbidden for this optional doc (min 1), so a
		// stored floor of 0 unambiguously means never-seen.
		if seen.RevocationSerial > 0 {
			return nil, seenKey, &StrippedError{Document: "revocation list", LastSeen: seen.RevocationSerial}
		}
	default:
		return nil, seenKey, fmt.Errorf("fetch revocation list: %w", rerr)
	}

	selected, narrowed, err := resolvePullSelection(index, opts.Selectors, opts.AllVersions)
	if err != nil {
		return nil, seenKey, err
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
		// build names this platform build in errors. Name and version are
		// quoted because they are still unvalidated upstream strings here; the
		// platform already matched the index schema's platform pattern.
		build := fmt.Sprintf("%q %q (%s)", sel.name, sel.version, platform.Display(sel.entry.Platform))
		data, err := backend.Fetch(ctx, sel.entry.Artifact)
		if err != nil {
			return nil, seenKey, fmt.Errorf("fetch artifact %s: %w", build, err)
		}
		sig, err := backend.FetchSignature(ctx, sel.entry.Artifact)
		if err != nil {
			return nil, seenKey, fmt.Errorf("fetch artifact signature %s: %w", build, err)
		}
		if err := verifyClaim(state, trust.RoleArtifact, data, sig, sel.name, sel.version, sel.entry.Platform, sel.entry.ContentHash); err != nil {
			return nil, seenKey, err
		}
		pkgDir, err := stagedPkgDir(stagingRoot, sel.name, sel.version, sel.entry.Platform)
		if err != nil {
			return nil, seenKey, err
		}
		attDir := filepath.Join(pkgDir, "attestations")
		if err := os.MkdirAll(attDir, 0o755); err != nil { //nolint:gosec // G301: operator-local staging dir
			return nil, seenKey, fmt.Errorf("create staging dir for %s: %w", build, err)
		}
		artPath := filepath.Join(pkgDir, sel.name+".tar.zst")
		if err := os.WriteFile(artPath, data, 0o644); err != nil { //nolint:gosec // G306: operator-local staging file
			return nil, seenKey, fmt.Errorf("stage artifact %s: %w", build, err)
		}
		for j := range sel.entry.Attestations {
			ref := &sel.entry.Attestations[j]
			if revocations != nil && revocations.IsAttestationRevoked(ref.ContentHash) {
				return nil, seenKey, fmt.Errorf("refusing to pull %s: attestation %s is revoked by the upstream revocation list", build, ref.ContentHash)
			}
			attData, err := backend.Fetch(ctx, ref.Artifact)
			if err != nil {
				return nil, seenKey, fmt.Errorf("fetch attestation %s: %w", ref.Artifact, err)
			}
			attSig, err := backend.FetchSignature(ctx, ref.Artifact)
			if err != nil {
				return nil, seenKey, fmt.Errorf("fetch attestation signature %s: %w", ref.Artifact, err)
			}
			if err := verifyClaim(state, trust.RoleAttestation, attData, attSig, sel.name, sel.version, "", ref.ContentHash); err != nil {
				return nil, seenKey, err
			}
			blobName := strings.TrimPrefix(ref.ContentHash, "blake3:") + ".att.json"
			if err := os.WriteFile(filepath.Join(attDir, blobName), attData, 0o644); err != nil { //nolint:gosec // G306: operator-local staging file
				return nil, seenKey, fmt.Errorf("stage attestation %s: %w", ref.Artifact, err)
			}
		}
		res.Packages = append(res.Packages, PulledPackage{
			Name: sel.name, Version: sel.version, ContentHash: sel.entry.ContentHash,
			ArtifactPath: artPath, AttDir: attDir,
		})
	}

	// Optional upstream trust bundle. Stage it verbatim (verified) for
	// carry-forward by `repo build` (2e-3a). The same absence rules as the
	// revocation list apply: absent and never seen means nothing to carry, and
	// absent after one was seen is a strip.
	bundleSerial := seen.BundleSerial
	bDoc, bSig, berr := backend.FetchTrustBundle(ctx)
	switch {
	case berr == nil:
		var bGraced bool
		if _, bundleSerial, bGraced, err = verifier.LoadBundle(bDoc, bSig, seen.BundleSerial, opts.AcceptExpiryUntil); err != nil {
			return nil, seenKey, fmt.Errorf("verify trust bundle: %w", err)
		}
		if bGraced {
			res.Graced = append(res.Graced, "trust bundle (grace until "+opts.AcceptExpiryUntil+")")
		}
		if revocations != nil {
			// Re-parse the signature-verified bytes to iterate builder keys (Bundle
			// exposes them only by lookup). Refuse carrying a revoked key forward —
			// carry-forward would otherwise launder the upstream's revocation.
			tb, perr := schema.ParseTrustBundle(bytes.NewReader(bDoc))
			if perr != nil {
				return nil, seenKey, fmt.Errorf("parse verified trust bundle: %w", perr)
			}
			for i := range tb.BuilderKeys {
				if revocations.IsBuilderKeyRevoked(tb.BuilderKeys[i].KeyID) {
					return nil, seenKey, fmt.Errorf("refusing to carry trust bundle forward: builder key %q is revoked by the upstream revocation list", tb.BuilderKeys[i].KeyID)
				}
			}
		}
		if err := os.MkdirAll(stagingRoot, 0o755); err != nil { //nolint:gosec // G301: operator-local staging dir
			return nil, seenKey, fmt.Errorf("create staging dir: %w", err)
		}
		tbPath := filepath.Join(stagingRoot, "trust-bundle.json")
		if err := os.WriteFile(tbPath, bDoc, 0o644); err != nil { //nolint:gosec // G306: operator-local staging file
			return nil, seenKey, fmt.Errorf("stage trust bundle: %w", err)
		}
		res.TrustBundlePath = tbPath
	case errors.Is(berr, source.ErrMetadataAbsent):
		// serial 0 is schema-forbidden for this optional doc (min 1), so a
		// stored floor of 0 unambiguously means never-seen.
		if seen.BundleSerial > 0 {
			return nil, seenKey, &StrippedError{Document: "trust bundle", LastSeen: seen.BundleSerial}
		}
	default:
		return nil, seenKey, fmt.Errorf("fetch trust bundle: %w", berr)
	}

	res.SeenKey = seenKey
	res.Seen = trust.Seen{
		TrustSerial:      trustSerial,
		IndexSerial:      indexSerial,
		BundleSerial:     bundleSerial,
		RevocationSerial: revSerial,
	}
	return res, seenKey, nil
}

// StoreFloors persists the verified serial floors of a mirror run's pull
// results under stateHome, one trust.Seen record per PullResult.SeenKey. Call
// it only after the whole run has succeeded.
//
// It is a ratchet. A sources file may list one upstream more than once, so the
// results are first merged per key by per-document maximum. Each key's current
// record is then re-read and only raised, never lowered, so a floor stored
// since this run's Pull loaded its baseline survives. A record that cannot be
// read or parsed fails the store rather than being overwritten.
//
// The re-read-then-store is not atomic on its own. The ratchet holds only
// while the caller holds the mirror's lock (<stateHome>/lock, taken by
// runMirrorPull for the whole run); without it two writers can interleave and
// the later store can lower the earlier one's floor.
func StoreFloors(stateHome string, results []*PullResult) error {
	merged := make(map[string]trust.Seen, len(results))
	order := make([]string, 0, len(results))
	for _, r := range results {
		cur, ok := merged[r.SeenKey]
		if !ok {
			order = append(order, r.SeenKey)
		}
		merged[r.SeenKey] = maxSerials(cur, r.Seen)
	}
	for _, key := range order {
		cur, err := trust.LoadSeen(stateHome, key)
		if err != nil {
			return fmt.Errorf("re-read anti-rollback state %s: %w", trust.SeenPath(stateHome, key), err)
		}
		if err := trust.StoreSeen(stateHome, key, maxSerials(cur, merged[key])); err != nil {
			return fmt.Errorf("record anti-rollback state %s: %w", trust.SeenPath(stateHome, key), err)
		}
	}
	return nil
}

// maxSerials raises base's four document serials to at least those in s,
// keeping base's other fields.
func maxSerials(base, s trust.Seen) trust.Seen {
	base.TrustSerial = max(base.TrustSerial, s.TrustSerial)
	base.IndexSerial = max(base.IndexSerial, s.IndexSerial)
	base.BundleSerial = max(base.BundleSerial, s.BundleSerial)
	base.RevocationSerial = max(base.RevocationSerial, s.RevocationSerial)
	return base
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
// together (dedup by key_id; a conflicting key_id fails closed). Every staged
// artifact of one package name from ONE source (each version, and each
// platform build of a version) is grouped under a single "name:" YAML key with
// one "- prebuilt:" list item per artifact. Refuses two
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

// stagedPkgDir returns the staging dir for one platform build of a package,
// refusing any name, version, or platform that could escape stagingRoot via
// path traversal. Package names are index map keys;
// schema.ValidatePackageName confines them to the package-name slug here too,
// so a name with path or YAML metacharacters fails closed at the staging
// boundary (protects the staged path, artifact filename, and the generated
// manifest's YAML key position) whatever the index schema admitted (defense in
// depth; mirrors verify.go's readTar traversal rejection).
//
// The layout is <name>/<version>/<platform-dir>, NOT <name>-<version>: a
// single delimiter join is ambiguous — ("a","b-1.0.0") and ("a-b","1.0.0") would
// both collapse to "a-b-1.0.0", letting a compromised upstream merge two packages
// into one attestations/ dir (cross-binding at ingest). The charset guards
// (schema.ValidatePackageName, safePkgVersion) plus the traversal check
// guarantee neither name nor version contains "/" or "..", so each is exactly
// one safe segment and distinct (name,version) pairs can never collide.
//
// <platform-dir> is the platform with "/" replaced by "-" (linux/amd64 becomes
// linux-amd64), or "any" for a platform-agnostic entry (plat == ""), so two
// platform builds of one version stage apart. The platform must pass the
// consumer grammar (2 or 3 [a-z0-9]+ segments), which keeps the mapping
// injective. A segment never contains "-", so flattening cannot merge two
// platforms. Every flattened platform contains a "-" and "any" does not, so
// the agnostic dir cannot alias a platform's. A literal "any" fails the
// grammar.
func stagedPkgDir(stagingRoot, name, version, plat string) (string, error) {
	for _, s := range []string{name, version} {
		if s == "" || s == "." || s == ".." || strings.ContainsAny(s, `/\`) || strings.Contains(s, "..") {
			return "", fmt.Errorf("refusing unsafe package name/version %q (path traversal)", s)
		}
	}
	if err := schema.ValidatePackageName(name); err != nil {
		return "", fmt.Errorf("refusing to stage: %w", err)
	}
	if !safePkgVersion.MatchString(version) {
		return "", fmt.Errorf("refusing package version %q: contains unsafe characters", version)
	}
	platDir := platform.Any
	if plat != "" {
		if err := platform.ValidateConsumer(plat); err != nil {
			return "", fmt.Errorf("refusing package %q %q: unsafe platform %q: %w", name, version, plat, err)
		}
		platDir = strings.ReplaceAll(plat, "/", "-")
	}
	dir := filepath.Join(stagingRoot, name, version, platDir)
	rootClean := filepath.Clean(stagingRoot)
	if dir != rootClean && !strings.HasPrefix(dir, rootClean+string(filepath.Separator)) {
		return "", fmt.Errorf("refusing package %q-%q: staging path escapes %q", name, version, stagingRoot)
	}
	return dir, nil
}

// verifyClaim checks a fetched blob against the source keyring under `role` and
// asserts its signed claim matches the expected index entry: name/version/hash
// for both roles, plus the platform for an artifact (wantPlatform is the
// entry's platform, "" = platform-agnostic). An attestation's transport claim
// carries no platform: it binds to its artifact by digest, which is already
// per-platform. The crypto is the SHARED trust kernel (state.Verify); this
// re-states only the small "claim matches the index" assertion (mirrors
// planner.verifyArtifact).
func verifyClaim(state trust.Keyring, role trust.Role, data []byte, sig, name, version, wantPlatform, wantHash string) error {
	claims, err := state.Verify(role, data, sig)
	if err != nil {
		return fmt.Errorf("signature verification failed for %s-%s: %w", name, version, err)
	}
	var cname, cversion, cplat, chash string
	if role == trust.RoleAttestation {
		cname, cversion, chash, err = claims.Attestation()
	} else {
		cname, cversion, cplat, chash, err = claims.Artifact()
	}
	if err != nil {
		return fmt.Errorf("%s-%s: %w", name, version, err)
	}
	if got := contentHash(data); got != wantHash {
		return fmt.Errorf("hash mismatch for %s-%s: index %s, actual %s", name, version, wantHash, got)
	}
	if cname != name || cversion != version || chash != wantHash {
		return fmt.Errorf("signed claim %s-%s/%s does not match index %s-%s/%s", cname, cversion, chash, name, version, wantHash)
	}
	if role != trust.RoleAttestation && cplat != wantPlatform {
		return fmt.Errorf("signed claim for %s-%s is for platform %s, index entry is for %s",
			name, version, platform.Display(cplat), platform.Display(wantPlatform))
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
// A selection is one index entry (one platform build), not one version, and a
// mirror never filters by platform. "Latest" is therefore the newest version
// per (name, platform). Platform-agnostic entries form their own group. When
// linux has 1.1.0 and darwin only 1.0.0, both builds are mirrored, so a client
// on either host finds its own newest build. A "name@version" pin selects every
// platform build of that version. Selections are ordered by name, then (for
// latest and pins) by platform; the agnostic group sorts first.
//
// An index that lists one (name, version, platform) more than once is
// refused before anything is selected, whichever packages are selected:
// repo build never publishes one, so the signed document is malformed.
//
// It also returns narrowing notes: whenever a "latest" resolution (empty
// selectors, or a bare "name" selector) leaves behind older versions that the
// upstream published for the same platform group, one note per group names
// them. A group's newest build is never reported as skipped. An explicit
// "name@version" selector never produces a note — the operator chose that
// outcome. Neither does an unpinned name under allVersions — nothing was
// dropped, so there is nothing to report.
//
// allVersions widens what an unpinned selection (empty selectors, or a bare
// "name") means, from "latest" to "every published version". It does not
// touch an explicit "name@version" selector: that is already unambiguous,
// so it is honoured as written regardless of allVersions.
func resolvePullSelection(index *schema.Index, selectors []string, allVersions bool) ([]pullSelection, []string, error) {
	if err := refuseDuplicateBuilds(index); err != nil {
		return nil, nil, err
	}
	// pick resolves name to "latest": the newest version within each
	// platform group (platform-agnostic entries are the "" group), ordered by
	// platform. It also returns the narrowing note of every group that
	// published versions older than the one picked.
	pick := func(name string) ([]pullSelection, []string, error) {
		entries, ok := index.Packages[name]
		if !ok || len(entries) == 0 {
			return nil, nil, fmt.Errorf("package %q not found in the upstream index", name)
		}
		best := map[string]int{}              // platform group → index of its newest entry
		bestV := map[string]*semver.Version{} // platform group → that entry's version
		versions := make([]*semver.Version, len(entries))
		for i := range entries {
			v, err := semver.NewVersion(entries[i].Version)
			if err != nil {
				return nil, nil, fmt.Errorf("package %q version %q is not semver", name, entries[i].Version)
			}
			versions[i] = v
			p := entries[i].Platform
			cur, seen := bestV[p]
			if !seen {
				best[p], bestV[p] = i, v
				continue
			}
			// Compare ignores build metadata and a "v" prefix, so 1.0.0+a and
			// 1.0.0+b tie; keep the lexically smaller spelling, as pickAll
			// orders them, so the pick does not depend on index order.
			if c := v.Compare(cur); c > 0 || c == 0 && entries[i].Version < entries[best[p]].Version {
				best[p], bestV[p] = i, v
			}
		}
		groups := make([]string, 0, len(best))
		for p := range best {
			groups = append(groups, p)
		}
		sort.Strings(groups)
		sels := make([]pullSelection, 0, len(groups))
		var notes []string
		for _, p := range groups {
			e := entries[best[p]]
			sels = append(sels, pullSelection{name: name, version: e.Version, entry: e})
			if note := narrowingNote(name, p, entries, versions, e.Version); note != "" {
				notes = append(notes, note)
			}
		}
		return sels, notes, nil
	}
	// pickAll is pick's sibling for the --all-versions path: it returns every
	// entry for name instead of each group's newest. Order is fixed (newest
	// version first, matching pick's own preference, then platform) rather
	// than left as map/index order, because the emitted manifest must be
	// byte-stable across runs; the resolver only needs the set, so this
	// ordering exists for a human reading index.json.
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
		sort.Slice(order, func(i, j int) bool {
			a, b := order[i], order[j]
			if c := versions[a].Compare(versions[b]); c != 0 {
				return c > 0
			}
			// Compare ignores build metadata, so 1.0.0+a and 1.0.0+b tie;
			// order them by spelling before falling back to platform.
			if entries[a].Version != entries[b].Version {
				return entries[a].Version < entries[b].Version
			}
			return entries[a].Platform < entries[b].Platform
		})
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
			sels, pickNotes, err := pick(name)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, sels...)
			notes = append(notes, pickNotes...)
		}
		// Stable: preserves pick/pickAll's order within a name across the
		// by-name sort (which only orders distinct names).
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
			sels, pickNotes, err := pick(name)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, sels...)
			notes = append(notes, pickNotes...)
			continue
		}
		// A pin selects every platform build of exactly that version,
		// ordered by platform so the emitted manifest is byte-stable.
		var pinned []pullSelection
		entries := index.Packages[name]
		for i := range entries {
			if entries[i].Version == ver {
				pinned = append(pinned, pullSelection{name: name, version: ver, entry: entries[i]})
			}
		}
		if len(pinned) == 0 {
			return nil, nil, fmt.Errorf("package %q version %q not found in the upstream index", name, ver)
		}
		sort.Slice(pinned, func(i, j int) bool { return pinned[i].entry.Platform < pinned[j].entry.Platform })
		out = append(out, pinned...)
	}
	return out, notes, nil
}

// refuseDuplicateBuilds fails when the index lists one (name, version,
// platform) more than once. repo build never publishes such an index, so a
// signed one is malformed. Per-platform "latest" would keep one copy and
// silently drop the other; a pin or --all-versions would stage both copies to
// one directory and hand repo build two prebuilt entries for a single
// artifact. Names are checked in sorted order so the error is deterministic.
func refuseDuplicateBuilds(index *schema.Index) error {
	names := make([]string, 0, len(index.Packages))
	for name := range index.Packages {
		names = append(names, name)
	}
	sort.Strings(names)
	type build struct{ version, platform string }
	for _, name := range names {
		seen := map[build]bool{}
		entries := index.Packages[name]
		for i := range entries {
			k := build{entries[i].Version, entries[i].Platform}
			if seen[k] {
				return fmt.Errorf("upstream index lists %q %q for platform %q more than once",
					name, k.version, platform.Display(k.platform))
			}
			seen[k] = true
		}
	}
	return nil
}

// narrowingNote returns an actionable note when a "latest" resolution chose
// picked as the newest version in name's platform group plat ("" is the
// platform-agnostic group) and that group also published older versions. The
// note names exactly what this pull did not mirror for that group and how to
// get it. Only entries in the group count, so a version that is another
// platform's newest build is never reported. Returns "" when picked is the
// group's only version. The agnostic group keeps the unqualified "name:"
// prefix; a platform group is named "name (os/arch):". versions holds each
// entry's parsed version; skipped versions are listed in semver order (1.9.0
// before 1.10.0), with semver-equal spellings ordered by spelling.
func narrowingNote(name, plat string, entries []schema.IndexEntry, versions []*semver.Version, picked string) string {
	var skippedIdx []int
	for i := range entries {
		if entries[i].Platform == plat && entries[i].Version != picked {
			skippedIdx = append(skippedIdx, i)
		}
	}
	if len(skippedIdx) == 0 {
		return ""
	}
	sort.Slice(skippedIdx, func(i, j int) bool {
		a, b := skippedIdx[i], skippedIdx[j]
		if c := versions[a].Compare(versions[b]); c != 0 {
			return c < 0
		}
		return entries[a].Version < entries[b].Version
	})
	skipped := make([]string, len(skippedIdx))
	for i, idx := range skippedIdx {
		skipped[i] = entries[idx].Version
	}
	label := name
	if plat != "" {
		label = name + " (" + plat + ")"
	}
	if len(skipped) == 1 {
		return fmt.Sprintf("%s: mirrored %s, did not mirror %s (select it with --package %s@%s)",
			label, picked, skipped[0], name, skipped[0])
	}
	return fmt.Sprintf("%s: mirrored %s, did not mirror %s (select each with --package %s@<version>)",
		label, picked, strings.Join(skipped, ", "), name)
}
