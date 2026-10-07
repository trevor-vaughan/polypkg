package repo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// buildTimestamp is the trusted-comment timestamp embedded in index and trust
// signatures. Fixed so repeated no-op builds produce byte-identical signatures
// (deterministic builds); the monotonic serial gives consumers ordering.
const buildTimestamp = "1970-01-01T00:00:00Z"

// DefaultValidFor is the validity window stamped into the signed index and
// trust document when --valid-for is not given. It is also the
// fallback window for a build cache that has no window recorded yet (see
// effectiveWindow).
const DefaultValidFor = 720 * time.Hour

// Result reports what a Build did.
type Result struct {
	Changed      bool
	SerialBefore uint64
	SerialAfter  uint64
	// Expires is the freshness bound now stamped into the published index
	// (RFC3339). On a no-op rebuild that reused the previous window this is that
	// earlier window, not one derived from this call's ValidFor.
	Expires string
	// ValidForApplied reports whether this call's ValidFor was stamped into the
	// published metadata. It is false exactly when the half-life rule reused
	// the still-fresh published window, which silently discards the caller's
	// requested duration.
	ValidForApplied bool
	// RestampAfter is the RFC3339 instant past which the next build re-stamps
	// Expires: the half-life of the window Expires was actually issued with,
	// which is not derivable from ValidFor when this call reused an earlier
	// window. Callers report it so an operator whose --valid-for was dropped can
	// see when it stops being dropped.
	RestampAfter string
	// TrustBundle is what this build did to trust-bundle.json: the bundle it
	// published, or its withdrawal. Nil when the bundle was left as it was.
	TrustBundle *TrustBundleChange
}

// BuildOptions tunes one Build invocation.
type BuildOptions struct {
	// ValidFor is the validity window stamped into the signed index and trust
	// document; consumers reject metadata past it. Zero or negative means the
	// 720h (30 day) default.
	ValidFor time.Duration
	// SkipAttestations publishes without per-package lint attestations (e.g.
	// the signing key deliberately lacks the attestation role). Cached
	// packages keep their previous attestation decision until their source
	// changes (see the cache-hit CAVEAT in Build).
	SkipAttestations bool
}

// repoLayout holds the manifest-derived paths and parsed manifest. It is the
// no-key subset shared by both Inspector and Builder.
type repoLayout struct {
	manifestDir string
	manifest    *schema.RepoManifest
	outputDir   string
	cachePath   string
}

// loadLayout opens the manifest, parses it, resolves output/cache paths, and
// runs the key-not-in-output guard. It does NOT decrypt the signing key.
func loadLayout(manifestPath, keyDir string) (repoLayout, error) {
	f, err := os.Open(manifestPath) //nolint:gosec // G304: path is user-supplied manifest location from --manifest flag
	if err != nil {
		return repoLayout{}, &PublishError{
			Msg:  "cannot open repo manifest",
			Hint: "run `polypkg repo init <dir>` first, or pass --manifest",
			Err:  err,
		}
	}
	defer func() { _ = f.Close() }()

	m, err := schema.ParseRepoManifest(f)
	if err != nil {
		return repoLayout{}, &PublishError{
			Msg:  "repo manifest is invalid",
			Hint: "check polypkg-repo.yaml against the polypkg.repo/v1 schema",
			Err:  err,
		}
	}

	return layoutFor(m, manifestPath, keyDir)
}

// layoutFor derives the output and cache paths for an already-parsed manifest
// and runs the key-not-in-output guard. Split out of loadLayout so a caller
// holding a manifest that is not on disk yet (Builder.SetManifest) resolves
// paths and clears the guard through exactly the same code.
func layoutFor(m *schema.RepoManifest, manifestPath, keyDir string) (repoLayout, error) {
	manifestDir := filepath.Dir(manifestPath)
	outputDir := resolveRel(manifestDir, m.Output)

	if err := guardKeyNotInOutput(outputDir, resolveRel(manifestDir, m.Key.Path), keyDir); err != nil {
		return repoLayout{}, err
	}

	return repoLayout{
		manifestDir: manifestDir,
		manifest:    m,
		outputDir:   outputDir,
		// filepath.Base on the source name keeps a stray separator from
		// relocating the build cache out of keyDir. ParseRepoManifest has
		// already rejected any non-slug source; this is the guard at the
		// interpolation site.
		cachePath: filepath.Join(keyDir, filepath.Base(m.Source)+".build-cache.json"),
	}, nil
}

// Inspector provides read-only probing of a repo manifest without decrypting
// the signing key. Use NewInspector for operations like `repo status` that do
// not write any files.
type Inspector struct {
	layout repoLayout
	// now is the clock the half-life decision reads. Always time.Now in
	// production; tests replace it to cross the half-life boundary of a real
	// published window without sleeping through it.
	now func() time.Time
}

// NewInspector loads and validates the manifest at manifestPath without
// decrypting the signing key. keyDir is used only to locate the build cache.
func NewInspector(manifestPath, keyDir string) (*Inspector, error) {
	lay, err := loadLayout(manifestPath, keyDir)
	if err != nil {
		return nil, err
	}
	return &Inspector{layout: lay, now: time.Now}, nil
}

// sourceCacheResult is the outcome of lookupSourceCache.
type sourceCacheResult int

const (
	// sourceCacheHit: the cached artifact can be republished as is.
	sourceCacheHit sourceCacheResult = iota
	// sourceCacheChanged: no cache entry, or the source no longer matches it.
	sourceCacheChanged
	// sourceCacheArtifactMissing: the source matches but its artifact is gone
	// from the output directory.
	sourceCacheArtifactMissing
)

// lookupSourceCache decides whether the source entry for package name, cached
// under key, with current fingerprint fp and tree srcDir, can republish its
// cached artifact from outputDir without repacking. Build and
// Inspector.Pending both call it, so `repo status` always agrees with what a
// build would do.
//
// SourceFingerprint hashes sizes and mtimes, not bytes, so an edit to
// polypkg.yaml that keeps both (platform: linux/amd64 -> linux/arm64, version:
// 1.0.0 -> 1.0.1) would otherwise republish the cached artifact, built from
// the old recipe. The recipe is re-read and its name, version and platform
// must still match what the cached artifact was published as (the cache
// records no name; the entry is published under name, so that is the match).
// A read error is a miss, leaving PackArtifact to report it.
func lookupSourceCache(cache *BuildCache, name, key, fp, srcDir, outputDir string) (CacheEntry, sourceCacheResult) {
	prev, ok := cache.Get(key)
	if !ok || prev.Fingerprint != fp {
		return CacheEntry{}, sourceCacheChanged
	}
	if _, err := os.Stat(filepath.Join(outputDir, prev.Artifact)); err != nil {
		return CacheEntry{}, sourceCacheArtifactMissing
	}
	src, err := ReadPackageSource(srcDir)
	if err != nil || src.Name != name || src.Version != prev.Version || src.Platform != prev.Platform {
		return CacheEntry{}, sourceCacheChanged
	}
	return prev, sourceCacheHit
}

// Pending reports whether Build() would change anything without writing any
// files, with a human-readable reason when it would. It is used by
// `repo status`. reason is "" when nothing is pending.
func (i *Inspector) Pending() (pending bool, reason string, err error) {
	cache, err := LoadBuildCache(i.layout.cachePath)
	if err != nil {
		return false, "", fmt.Errorf("load build cache: %w", err)
	}

	// Never built.
	if cache.Serial == 0 {
		return true, "repository has never been built", nil
	}

	// Check for any new or changed packages, collecting each package's cache key
	// so the removal sweep runs in the same pass. A source package keys on its
	// manifest-relative path (fingerprinted by SourceFingerprint); a prebuilt
	// package keys on its fetched artifact's content hash — mirroring Build's two
	// branches so `repo status` agrees with what a build would actually do.
	manifestKeys := make(map[string]bool, len(i.layout.manifest.Packages))
	for name, entries := range i.layout.manifest.Packages {
		for _, pkg := range entries {
			if pkg.Prebuilt == nil {
				srcDir := resolveRel(i.layout.manifestDir, pkg.Source)
				fp, ferr := SourceFingerprint(srcDir)
				if ferr != nil {
					return false, "", &PublishError{
						Msg:  fmt.Sprintf("cannot fingerprint package %q source", name),
						Hint: fmt.Sprintf("check that packages.%s.source (%s) exists and is readable", name, pkg.Source),
						Err:  ferr,
					}
				}
				manifestKeys[pkg.Source] = true
				switch _, res := lookupSourceCache(cache, name, pkg.Source, fp, srcDir, i.layout.outputDir); res {
				case sourceCacheChanged:
					return true, fmt.Sprintf("package %q source is new or changed", name), nil
				case sourceCacheArtifactMissing:
					return true, fmt.Sprintf("package %q artifact is missing from the output directory", name), nil
				}
				continue
			}

			artPath := resolveRel(i.layout.manifestDir, pkg.Prebuilt.Artifact)
			artifact, rerr := os.ReadFile(artPath) //nolint:gosec // G304: artPath is the operator-declared prebuilt artifact
			if rerr != nil {
				return false, "", &PublishError{
					Msg:  fmt.Sprintf("cannot read prebuilt artifact for %q", name),
					Hint: fmt.Sprintf("check packages.%s.prebuilt.artifact (%s)", name, pkg.Prebuilt.Artifact),
					Err:  rerr,
				}
			}
			cacheKey := ContentHash(artifact)
			manifestKeys[cacheKey] = true
			prev, ok := cache.Get(cacheKey)
			if !ok || prev.Fingerprint != cacheKey {
				return true, fmt.Sprintf("package %q prebuilt artifact is new or changed", name), nil
			}
			// Artifact file must still be present in the output dir.
			if _, statErr := os.Stat(filepath.Join(i.layout.outputDir, prev.Artifact)); statErr != nil {
				return true, fmt.Sprintf("package %q artifact is missing from the output directory", name), nil
			}
		}
	}

	// Check for any packages that have been removed from the manifest but are
	// still tracked in the cache (they'd change the index).
	for key := range cache.Entries {
		if !manifestKeys[key] {
			return true, fmt.Sprintf("package %q was removed from the manifest", key), nil
		}
	}

	// The trust bundle changes without any package changing when a
	// sigstore_roots file or a carried trust_bundle is added, edited, or
	// dropped; Build publishes (or withdraws) it at a new serial, so status must
	// say so.
	tb, err := collectTrustBundle(i.layout)
	if err != nil {
		return false, "", err
	}
	switch changed, orphaned := tb.publishedChange(i.layout.outputDir); {
	case changed:
		return true, "trust bundle is new or changed", nil
	case orphaned:
		return true, "published trust bundle is no longer backed by the manifest and will be withdrawn", nil
	}

	// No content change — but Build restamps expires (and bumps the serial)
	// when the published expiry is absent, unparseable, or below its half-life
	// (half-life renewal), so status must report that as pending too. The window
	// comes from the build cache, which records what the build that published
	// that expiry actually used: `repo status` has no --valid-for flag, and
	// assuming the 720h default here made every repository published with a
	// shorter window report pending the instant it was built.
	if !expiryFresh(i.now(), publishedExpires(i.layout.outputDir), effectiveWindow(cache.ValidFor)) {
		return true, "metadata expiry refresh due", nil
	}

	return false, "", nil
}

// TrustBundleChange reports what the next build would do to the published
// trust-bundle.json: nil when it would leave it as it is.
func (i *Inspector) TrustBundleChange() (*TrustBundleChange, error) {
	tb, err := collectTrustBundle(i.layout)
	if err != nil {
		return nil, err
	}
	return tb.summary(tb.publishedChange(i.layout.outputDir))
}

// Builder reconciles a repo manifest into a signed output directory.
type Builder struct {
	insp *Inspector
	key  *Keypair
}

// NewBuilder loads the manifest at manifestPath and decrypts the signing key.
// keyDir is the directory that holds the build cache (and should contain the
// key file); password unlocks the encrypted key.
func NewBuilder(manifestPath, keyDir, password string) (*Builder, error) {
	insp, err := NewInspector(manifestPath, keyDir)
	if err != nil {
		return nil, err
	}

	keyPath := resolveRel(insp.layout.manifestDir, insp.layout.manifest.Key.Path)
	kp, err := LoadKey(keyPath, password)
	if err != nil {
		return nil, LoadKeyError(keyPath, err)
	}

	return &Builder{insp: insp, key: kp}, nil
}

// SetManifest points this Builder at an in-memory manifest, keeping the signing
// key it already decrypted. It exists for callers that must reconcile against a
// manifest edit before that edit is persisted (`repo add`, `repo remove`): they
// construct the Builder first, so a manifest that will not parse or a key that
// will not unlock is rejected before anything is written; then they build
// against the edited manifest and write polypkg-repo.yaml only once the build
// has succeeded. A build that fails therefore leaves the manifest untouched,
// and the key is decrypted once either way.
//
// manifestPath and keyDir must name the manifest and build cache the Builder
// was constructed with; passing a different pair repoints the Builder rather
// than re-basing it.
func (b *Builder) SetManifest(m *schema.RepoManifest, manifestPath, keyDir string) error {
	lay, err := layoutFor(m, manifestPath, keyDir)
	if err != nil {
		return err
	}
	// Assign into the existing Inspector rather than replacing it, so the clock
	// the half-life rule reads survives the repoint.
	b.insp.layout = lay
	return nil
}

// Pending delegates to the embedded Inspector so that callers of Builder can
// still check pending state without going through Build.
func (b *Builder) Pending() (pending bool, reason string, err error) {
	return b.insp.Pending()
}

// resolveRel returns p as-is if absolute, otherwise joins it to base.
func resolveRel(base, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

// InsideOutputDir reports whether path is outputDir itself or lies beneath it,
// comparing absolute forms. It is the one containment test for "would this be
// published": guardKeyNotInOutput uses it, and so does any caller that keeps
// operator-local state beside the key (mirror pull's anti-rollback floors).
func InsideOutputDir(outputDir, path string) bool {
	absOut, _ := filepath.Abs(outputDir)
	ap, _ := filepath.Abs(path)
	sep := string(os.PathSeparator)
	return ap == absOut || strings.HasPrefix(ap+sep, absOut+sep)
}

// guardKeyNotInOutput refuses to proceed if the secret key or build cache would
// live inside the published directory, which would expose private material.
func guardKeyNotInOutput(outputDir, keyPath, keyDir string) error {
	for _, p := range []string{keyPath, keyDir} {
		if InsideOutputDir(outputDir, p) {
			return &PublishError{
				Msg:  "signing key or build cache would be inside the published output directory",
				Hint: "store keys outside `output` (use --key-dir or move key.path); never serve your private key",
			}
		}
	}
	return nil
}

// Build reconciles every package declared in the manifest against the build
// cache, (re)packs and signs any that changed, regenerates index.json and
// trust.json with minisigs, and exports trust_root.pub. It bumps the
// monotonic serial only when published content actually changes. Artifacts are
// written (temp+rename) before the index that references them. The index, trust
// document, their signatures, and the trust root are published as one
// staged-then-committed set (writeAtomicBatch): a write failure aborts before
// any of them is renamed into place, so a failed build never leaves a document
// updated with a stale signature. Artifacts are content-addressed under pool/
// (a republish writes a NEW blob; old blobs persist immutably so older signed
// indexes keep resolving), so rewriting an existing blob is an idempotent
// same-bytes overwrite. The residual non-atomicity is the rare rename-phase
// failure; the next build self-heals (the cache is saved only on success, so a
// failed build re-packs).
func (b *Builder) Build(opts BuildOptions) (Result, error) {
	if opts.ValidFor <= 0 {
		opts.ValidFor = DefaultValidFor
	}
	lay := b.insp.layout
	cache, err := LoadBuildCache(lay.cachePath)
	if err != nil {
		return Result{}, fmt.Errorf("load build cache: %w", err)
	}
	before := cache.Serial

	// The serial lives only in the build cache, which LoadBuildCache resets to 0
	// on a missing or corrupt file. Floor it at the serial already published in
	// the output directory so a lost cache cannot regress — and thus reuse — a
	// serial. A reused serial means two differently-signed indexes share a
	// number, letting a mirror pin consumers to the stale one (defeating the
	// consumer's anti-rollback check).
	if pub := publishedSerial(lay.outputDir); pub > before {
		before = pub
	}

	// The revision ordinal has the same cache-loss exposure as the serial: it
	// is derived from the cache, so a lost cache would reset a republished
	// version's ordinal to 1 even though the published index says otherwise.
	// Probe the published index once and use it as the floor when the cache
	// carries no usable entry (see the revision derivation in the loop below).
	pubIdx := publishedIndex(lay.outputDir)

	// The repo-level trust bundle: roots converted from sigstore_roots plus the
	// builder keys and roots every prebuilt entry carries in, re-emitted under
	// the local key. Collected before anything is written, so a bad
	// sigstore_roots file or carried bundle fails the build with the output
	// directory untouched.
	tb, err := collectTrustBundle(lay)
	if err != nil {
		return Result{}, err
	}
	// What this build does to the published trust-bundle.json, decided now,
	// while the output directory still holds the previous build's bundle.
	bundleChanged, bundleOrphaned := tb.publishedChange(lay.outputDir)
	tbChange, err := tb.summary(bundleChanged, bundleOrphaned)
	if err != nil {
		return Result{}, err
	}

	// Pool blobs are content-addressed under <output>/pool and never
	// overwritten; the signed index is the only mutable pointer to them.
	if err := os.MkdirAll(filepath.Join(lay.outputDir, "pool"), 0o755); err != nil { //nolint:gosec // G301: output dir is served over HTTP; 0755 is intentional
		return Result{}, &PublishError{
			Msg:  "cannot create output directory",
			Hint: "check permissions on the output directory and its parent",
			Err:  err,
		}
	}

	// Process packages in sorted order for deterministic index output.
	names := make([]string, 0, len(lay.manifest.Packages))
	for name := range lay.manifest.Packages {
		names = append(names, name)
	}
	sort.Strings(names)

	idx := schema.Index{
		Schema:   schema.IndexSchemaID,
		Packages: map[string][]schema.IndexEntry{},
	}

	// newEntries will replace cache.Entries so removed packages drop out.
	newEntries := make(map[string]CacheEntry, len(names))
	changed := false
	// origins records which polypkg-repo.yaml entry each published entry came
	// from, so a refusal of the whole index can name the entries to change.
	origins := map[string][]entryOrigin{}
	publish := func(name string, entry schema.IndexEntry, from string) {
		idx.Packages[name] = append(idx.Packages[name], entry)
		origins[name] = append(origins[name], entryOrigin{version: entry.Version, from: from})
	}

	for _, name := range names {
		// Every entry under one name is checked against the per-name build
		// rules (see entryRules) on all four paths below — prebuilt and source,
		// cache hit and fresh pack — before it is published.
		rules := entryRules{name: name}

		for _, pkg := range lay.manifest.Packages[name] {
			if pkg.Prebuilt != nil {
				w, hit, err := b.ingestPackage(lay, name, pkg.Prebuilt, cache)
				if err != nil {
					return Result{}, err
				}
				// w.version and w.platform are set on both the cache-hit and
				// cache-miss return paths of ingestPackage, so checking here (before
				// the reuse branch) covers a cache-hit build too, not just a fresh pack.
				if err := rules.admit(w.version, w.platform, pkg.Prebuilt.Artifact, true); err != nil {
					return Result{}, err
				}
				if hit.reuse {
					publish(name, hit.entry, fmt.Sprintf("prebuilt %q", pkg.Prebuilt.Artifact))
					newEntries[w.cacheKey] = hit.cacheEntry
					continue
				}
				rev := nextRevision(cache, pubIdx, w.cacheKey, name, w.version, w.platform, w.contentHash)
				entry, ce, err := b.emitPackage(lay.outputDir, w, rev)
				if err != nil {
					return Result{}, err
				}
				publish(name, entry, fmt.Sprintf("prebuilt %q", pkg.Prebuilt.Artifact))
				newEntries[w.cacheKey] = ce
				changed = true
				continue
			}

			srcDir := resolveRel(lay.manifestDir, pkg.Source)
			fp, err := SourceFingerprint(srcDir)
			if err != nil {
				return Result{}, &PublishError{
					Msg:  fmt.Sprintf("cannot fingerprint package %q source", name),
					Hint: fmt.Sprintf("check that packages.%s.source (%s) exists and is readable", name, pkg.Source),
					Err:  err,
				}
			}

			if prev, res := lookupSourceCache(cache, name, pkg.Source, fp, srcDir, lay.outputDir); res == sourceCacheHit {
				// A cache hit skips PackArtifact, so the version and platform
				// come from the cache entry: the rules must run here too, or a
				// second entry that also hits cache never reaches the
				// post-PackArtifact check below.
				if err := rules.admit(prev.Version, prev.Platform, pkg.Source, false); err != nil {
					return Result{}, err
				}
				publish(name, prev.indexEntry(), fmt.Sprintf("source %q", pkg.Source))
				newEntries[pkg.Source] = prev
				continue
			}

			artifact, pkgParsed, err := PackArtifact(srcDir)
			var refusal *PackRefusal
			if errors.As(err, &refusal) {
				return Result{}, &PublishError{
					Msg:  fmt.Sprintf("cannot pack package %q: %s", name, refusal.Msg),
					Hint: refusal.Hint,
					Err:  err,
				}
			}
			if err != nil {
				return Result{}, &PublishError{
					Msg:  fmt.Sprintf("cannot pack package %q", name),
					Hint: fmt.Sprintf("check the package source at packages.%s.source (%s)", name, pkg.Source),
					Err:  err,
				}
			}
			if pkgParsed.Name != name {
				return Result{}, &PublishError{
					Msg:  fmt.Sprintf("manifest key %q does not match package name %q", name, pkgParsed.Name),
					Hint: "the key in packages.<name> must match the name field in the package's polypkg.yaml",
				}
			}
			if err := rules.admit(pkgParsed.Version, pkgParsed.Platform, pkg.Source, false); err != nil {
				return Result{}, err
			}
			ch := ContentHash(artifact)
			refs, blobs, err := b.sourceAttestations(srcDir, pkg.Source, name, pkgParsed.Version, ch, artifact, opts.SkipAttestations)
			if err != nil {
				return Result{}, err
			}
			w := packageWork{
				name: name, version: pkgParsed.Version, platform: pkgParsed.Platform, contentHash: ch, artifact: artifact,
				fingerprint: fp, cacheKey: pkg.Source, attRefs: refs, attBlobs: blobs, pkg: pkgParsed,
			}
			rev := nextRevision(cache, pubIdx, pkg.Source, name, w.version, w.platform, ch)
			entry, ce, err := b.emitPackage(lay.outputDir, w, rev)
			if err != nil {
				return Result{}, err
			}
			publish(name, entry, fmt.Sprintf("source %q", pkg.Source))
			newEntries[pkg.Source] = ce
			changed = true
		}
	}

	// Mirror staging and pkg import lay packages out as <name>/<version>/, so
	// a published index must not hold two names, or two versions of one name,
	// that a case-insensitive filesystem would merge.
	if cf := schema.CaseFoldCollision(&idx); cf != nil {
		return Result{}, caseFoldRefusal(cf, origins)
	}

	// Stamp the freshness bound. computeExpires reuses the published
	// expiry on a pure no-op rebuild so the byte-compare below still sees
	// identical index bytes (serial-stable); a content change, or a published
	// document past its own half-life, restamps, and the byte-compare then bumps
	// the serial — TUF-style re-signing.
	//
	// window tracks the validity window that the expiry we end up publishing was
	// stamped with: the one already recorded in the cache if we reuse that
	// expiry, this call's ValidFor if we restamp. It is saved back to the cache
	// below so the next build — and `repo status`, which has no --valid-for flag
	// of its own — applies the half-life rule against the real window.
	now := b.insp.now()
	window := effectiveWindow(cache.ValidFor)
	expires, reusedExpires := computeExpires(now, lay.outputDir, changed, opts.ValidFor, window)
	if !reusedExpires {
		window = opts.ValidFor
	}
	idx.Expires = expires
	// Reuse is observable to the caller: opts.ValidFor was not honored, and the
	// CLI says so rather than exiting 0 on a flag it dropped.
	validForApplied := !reusedExpires

	// Marshal the index.
	idxJSON, err := json.Marshal(&idx)
	if err != nil {
		return Result{}, fmt.Errorf("marshal index: %w", err)
	}

	// Determine the new serial. A first-ever build (before==0), any package
	// rebuild, a byte-level change in the index, or a signing-key rotation all
	// bump the serial. The trust_root.pub comparison catches the key-rotation
	// case: if the on-disk pub file doesn't match the currently loaded key, the
	// trust root is stale and must be re-emitted with a new serial.
	// An orphaned trust-bundle.json (published earlier, nothing to publish now)
	// counts as a change so the trust set is re-signed at a new serial; it is
	// pruned after publish.
	serial := before
	idxPath := filepath.Join(lay.outputDir, "index.json")
	trustRootPubPath := filepath.Join(lay.outputDir, "trust_root.pub")
	currentPubFile := []byte(b.key.PublicKeyFile("polypkg " + lay.manifest.Source + " trust root"))
	if before == 0 || changed || bundleChanged || bundleOrphaned || !fileHasContent(idxPath, idxJSON) || !fileHasContent(trustRootPubPath, currentPubFile) {
		changed = true
		serial = before + 1
	}

	// Assemble the merged repo-level trust bundle with the FINAL serial + expires.
	mergedBundle := buildCarriedBundle(lay.manifest.Source, serial, expires, tb.keys, tb.order, tb.roots)

	// Build the trust document with the new serial.
	trust := schema.TrustDoc{
		Schema:   "polypkg.trust/v2",
		Source:   lay.manifest.Source,
		Serial:   serial,
		IssuedAt: buildTimestamp,
		Expires:  expires,
		Keys: []schema.TrustKey{{
			ID:     b.key.KeyIDHex(),
			Pubkey: b.key.PublicKeyBase64(),
			Roles:  []string{"index", "artifact", "attestation"},
		}},
	}
	trustJSON, err := json.Marshal(&trust)
	if err != nil {
		return Result{}, fmt.Errorf("marshal trust document: %w", err)
	}

	if changed {
		idxSig := b.key.SignIndex(serial, buildTimestamp, idxJSON)
		trustSig := b.key.SignTrust(serial, trustJSON)
		pubKey := b.key.PublicKeyFile("polypkg " + lay.manifest.Source + " trust root")

		// Publish the index, trust document, their signatures, and the trust
		// root as one staged-then-committed set so a write failure (the common
		// out-of-space/permission case) cannot leave a document updated but its
		// signature stale — which would make consumers reject the source.
		files := []publishFile{
			{path: filepath.Join(lay.outputDir, "index.json"), body: idxJSON},
			{path: filepath.Join(lay.outputDir, "index.json.minisig"), body: []byte(idxSig)},
			{path: filepath.Join(lay.outputDir, "trust.json"), body: trustJSON},
			{path: filepath.Join(lay.outputDir, "trust.json.minisig"), body: []byte(trustSig)},
			{path: filepath.Join(lay.outputDir, "trust_root.pub"), body: []byte(pubKey)},
		}
		if mergedBundle != nil {
			tbJSON, merr := json.Marshal(mergedBundle)
			if merr != nil {
				return Result{}, fmt.Errorf("marshal carried trust bundle: %w", merr)
			}
			tbSig := b.key.SignTrustBundle(serial, tbJSON)
			files = append(files,
				publishFile{path: filepath.Join(lay.outputDir, "trust-bundle.json"), body: tbJSON},
				publishFile{path: filepath.Join(lay.outputDir, "trust-bundle.json.minisig"), body: []byte(tbSig)},
			)
		}
		if err := writeAtomicBatch(files); err != nil {
			return Result{}, &PublishError{Msg: "publish repository metadata", Err: err}
		}
		if bundleOrphaned {
			if err := pruneOrphanTrustBundle(lay.outputDir); err != nil {
				return Result{}, &PublishError{Msg: "prune orphaned trust bundle", Err: err}
			}
		}
	}

	// Persist updated cache (removed packages drop out via newEntries replacement).
	cache.Serial = serial
	cache.Entries = newEntries
	cache.ValidFor = window
	if err := cache.Save(lay.cachePath); err != nil {
		return Result{}, fmt.Errorf("save build cache: %w", err)
	}

	// The published expiry is our own freshly formatted value, so the parse
	// cannot fail; guard anyway rather than report a bogus instant.
	restampAfter := ""
	if t, perr := time.Parse(time.RFC3339, expires); perr == nil {
		restampAfter = t.Add(-window / 2).UTC().Format(time.RFC3339)
	}

	return Result{
		Changed:         changed,
		SerialBefore:    before,
		SerialAfter:     serial,
		Expires:         expires,
		ValidForApplied: validForApplied,
		RestampAfter:    restampAfter,
		TrustBundle:     tbChange,
	}, nil
}

// writeAtomic writes body to path via a temp file + rename so a partial write
// is never observable by concurrent readers. All published artifacts use 0o644.
func writeAtomic(path string, body []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil { //nolint:gosec // G306: 0644 is correct for publicly served repository files
		return err
	}
	return os.Rename(tmp, path)
}

// publishFile is one path/body pair for writeAtomicBatch.
type publishFile struct {
	path string
	body []byte
}

// writeAtomicBatch publishes a set of files as close to atomically as a plain
// filesystem allows: it writes every file to a temp sibling first, and only
// once all temps are written does it rename them into place. A failure during
// the write phase (the common case — out of space, permissions) aborts before
// any rename, so the previously published set is left untouched and internally
// consistent; staged temps are cleaned up. A failure during the rename phase
// (rare — same directory, no allocation) can still leave a partial set, which
// the next build self-heals.
func writeAtomicBatch(files []publishFile) error {
	staged := make([]string, 0, len(files))
	for _, f := range files {
		tmp := f.path + ".tmp"
		if err := os.WriteFile(tmp, f.body, 0o644); err != nil { //nolint:gosec // G306: 0644 is correct for publicly served repository files
			for _, s := range staged {
				_ = os.Remove(s)
			}
			return err
		}
		staged = append(staged, tmp)
	}
	for i, f := range files {
		if err := os.Rename(f.path+".tmp", f.path); err != nil {
			// Best-effort cleanup of temps not yet committed; already-renamed
			// files stay (the next build re-commits the full set).
			for _, s := range staged[i:] {
				_ = os.Remove(s)
			}
			return fmt.Errorf("commit %s: %w", filepath.Base(f.path), err)
		}
	}
	return nil
}

// publishedTrustBundleExists reports whether outputDir currently holds a
// published trust-bundle.json (from a prior carried-provenance build). Used to
// detect an orphan that must be pruned when the current build carries none.
func publishedTrustBundleExists(outputDir string) bool {
	_, err := os.Stat(filepath.Join(outputDir, "trust-bundle.json"))
	return err == nil
}

// pruneOrphanTrustBundle removes a prior run's published trust-bundle.json and
// its detached signature. Idempotent: an absent file is not an error. Called
// when the current build carries no trust bundle, so a stale one would keep
// vouching for upstream builder keys the operator has dropped.
func pruneOrphanTrustBundle(outputDir string) error {
	for _, name := range []string{"trust-bundle.json", "trust-bundle.json.minisig"} {
		if err := os.Remove(filepath.Join(outputDir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// effectiveWindow resolves a validity window recorded in the build cache,
// falling back to the 720h default when none is recorded — a cache written
// before the window was recorded, or one that was reset. That fallback is the
// assumption the half-life rule made before the window was recorded at all, so
// an unrecorded window keeps its previous behaviour rather than acquiring a new
// one.
func effectiveWindow(window time.Duration) time.Duration {
	if window <= 0 {
		return DefaultValidFor
	}
	return window
}

// expiryFresh reports whether a published expiry is still above its own
// half-life. It is the single implementation of the expiry renewal rule:
// Build calls it to decide whether to reuse the published expiry, and
// Inspector.Pending calls it to predict that decision. One function is what
// keeps `repo status` and `repo build` from disagreeing about whether an expiry
// refresh is due.
//
// window is the validity window the published expiry was stamped with (from the
// build cache, resolved through effectiveWindow) — NOT the window the current
// call requested. A document is reused until it passes its own half-life;
// measuring against the caller's window instead would let a build with a
// shorter window restamp a document that is still fresh, and a probe with no
// window at all (`repo status`) guess wrong every time.
//
// An empty or unparseable expiry is not fresh: Build restamps it, so Pending
// must report it.
func expiryFresh(now time.Time, publishedExpiry string, window time.Duration) bool {
	t, err := time.Parse(time.RFC3339, publishedExpiry)
	if err != nil {
		return false
	}
	return t.Sub(now) > window/2
}

// computeExpires returns the RFC3339 expiry for this publish, and whether it
// reused the currently published one. It reuses when nothing changed and the
// published document is still above its own half-life, so no-op rebuilds stay
// byte-identical (and serial-stable); otherwise it stamps a fresh now+validFor.
//
// publishedWindow is the window the currently published expiry was stamped
// with; validFor is the window to stamp if this call does restamp.
func computeExpires(now time.Time, outputDir string, contentChanged bool, validFor, publishedWindow time.Duration) (expires string, reused bool) {
	cur := publishedExpires(outputDir)
	if !contentChanged && expiryFresh(now, cur, publishedWindow) {
		return cur, true
	}
	return now.UTC().Add(validFor).Format(time.RFC3339), false
}

// publishedExpires reads the expires of the currently published index, ""
// when absent or unparseable (first v2 build, or a fresh repo).
func publishedExpires(outputDir string) string {
	raw, err := os.ReadFile(filepath.Join(outputDir, "index.json")) //nolint:gosec // G304: output dir from validated manifest; our own prior published doc
	if err != nil {
		return ""
	}
	var probe struct {
		Expires string `json:"expires"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		return ""
	}
	return probe.Expires
}

// publishedIndex parses the currently published index.json, nil when absent or
// unparseable (first build, or a fresh repo). Like publishedSerial it reads the
// publisher's own prior output and is used only as a floor — for the per-package
// revision ordinal — so a best-effort nil on any error is correct.
func publishedIndex(outputDir string) *schema.Index {
	raw, err := os.ReadFile(filepath.Join(outputDir, "index.json")) //nolint:gosec // G304: output dir from validated manifest; our own prior published doc
	if err != nil {
		return nil
	}
	var idx schema.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil
	}
	return &idx
}

// publishedSerial returns the serial recorded in the output directory's
// trust.json, or 0 if it is absent or unreadable. It reads the publisher's own
// prior output and is used only as a monotonic floor for the next serial, so a
// best-effort read (0 on any error) is correct — it never fails the build.
func publishedSerial(outputDir string) uint64 {
	data, err := os.ReadFile(filepath.Join(outputDir, "trust.json")) //nolint:gosec // G304: output dir from validated manifest; our own prior published doc
	if err != nil {
		return 0
	}
	var td struct {
		Serial uint64 `json:"serial"`
	}
	if err := json.Unmarshal(data, &td); err != nil {
		return 0
	}
	return td.Serial
}

// fileHasContent returns true iff the file at path exists and its contents are
// byte-equal to want.
func fileHasContent(path string, want []byte) bool {
	got, err := os.ReadFile(path) //nolint:gosec // G304: path is an output directory path derived from the validated manifest
	if err != nil {
		return false
	}
	return bytes.Equal(got, want)
}

// entryOrigin is the polypkg-repo.yaml entry one published index entry came
// from: its version, and "source <path>" or "prebuilt <artifact>".
type entryOrigin struct {
	version string
	from    string
}

// caseFoldRefusal turns a CaseFoldCollision error into the user-facing
// refusal, naming both colliding spellings and the polypkg-repo.yaml entries
// that produced them. A name or version comes from each package's own
// polypkg.yaml, so that is where the hint sends the author.
func caseFoldRefusal(cf *schema.CaseFoldCollisionError, origins map[string][]entryOrigin) *PublishError {
	if cf.Package == "" {
		describe := func(name string) string {
			froms := make([]string, 0, len(origins[name]))
			for _, o := range origins[name] {
				froms = append(froms, o.from)
			}
			return fmt.Sprintf("%q (packages.%s: %s)", name, name, strings.Join(froms, ", "))
		}
		return &PublishError{
			Msg: fmt.Sprintf("package names %s and %s differ only in letter case, so they would share a directory on a case-insensitive filesystem",
				describe(cf.First), describe(cf.Second)),
			Hint: "rename one package in its polypkg.yaml and under packages: in polypkg-repo.yaml, or remove one of the entries from polypkg-repo.yaml",
			Err:  cf,
		}
	}
	describe := func(version string) string {
		var froms []string
		for _, o := range origins[cf.Package] {
			if o.version == version {
				froms = append(froms, o.from)
			}
		}
		return fmt.Sprintf("%q (%s)", version, strings.Join(froms, ", "))
	}
	return &PublishError{
		Msg: fmt.Sprintf("package %q versions %s and %s differ only in letter case, so they would share a directory on a case-insensitive filesystem",
			cf.Package, describe(cf.First), describe(cf.Second)),
		Hint: "change the version in one package's polypkg.yaml, or remove one of the entries from polypkg-repo.yaml",
		Err:  cf,
	}
}
