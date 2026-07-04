package repo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/pkglint"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// buildTimestamp is the trusted-comment timestamp embedded in index and trust
// signatures. Fixed so repeated no-op builds produce byte-identical signatures
// (deterministic builds); the monotonic serial gives consumers ordering.
const buildTimestamp = "1970-01-01T00:00:00Z"

// DefaultValidFor is the validity window stamped into the signed index and
// trust document when --valid-for is not given (D13/D-C1). Pending() uses it
// to predict the half-window renewal restamp, so `repo status` and
// `repo build` agree on whether an expiry refresh is due.
const DefaultValidFor = 720 * time.Hour

// Result reports what a Build did.
type Result struct {
	Changed      bool
	SerialBefore uint64
	SerialAfter  uint64
}

// BuildOptions tunes one Build invocation.
type BuildOptions struct {
	// ValidFor is the validity window stamped into the signed index and trust
	// document (D13). Zero or negative means the 720h (30 day) default.
	ValidFor time.Duration
	// SkipAttestations publishes without per-package lint attestations (D-C3:
	// e.g. the signing key deliberately lacks the attestation role). Cached
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

	manifestDir := filepath.Dir(manifestPath)
	outputDir := resolveRel(manifestDir, m.Output)

	if err := guardKeyNotInOutput(outputDir, resolveRel(manifestDir, m.Key.Path), keyDir); err != nil {
		return repoLayout{}, err
	}

	return repoLayout{
		manifestDir: manifestDir,
		manifest:    m,
		outputDir:   outputDir,
		cachePath:   filepath.Join(keyDir, m.Source+".build-cache.json"),
	}, nil
}

// Inspector provides read-only probing of a repo manifest without decrypting
// the signing key. Use NewInspector for operations like `repo status` that do
// not write any files.
type Inspector struct {
	layout repoLayout
}

// NewInspector loads and validates the manifest at manifestPath without
// decrypting the signing key. keyDir is used only to locate the build cache.
func NewInspector(manifestPath, keyDir string) (*Inspector, error) {
	lay, err := loadLayout(manifestPath, keyDir)
	if err != nil {
		return nil, err
	}
	return &Inspector{layout: lay}, nil
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

	// Check for any new or changed package sources.
	for name, pkg := range i.layout.manifest.Packages {
		srcDir := resolveRel(i.layout.manifestDir, pkg.Source)
		fp, err := SourceFingerprint(srcDir)
		if err != nil {
			return false, "", &PublishError{
				Msg:  fmt.Sprintf("cannot fingerprint package %q source", name),
				Hint: fmt.Sprintf("check that packages.%s.source (%s) exists and is readable", name, pkg.Source),
				Err:  err,
			}
		}
		prev, ok := cache.Get(pkg.Source)
		if !ok || prev.Fingerprint != fp {
			return true, fmt.Sprintf("package %q source is new or changed", name), nil
		}
		// Artifact file must still be present in the output dir.
		if _, statErr := os.Stat(filepath.Join(i.layout.outputDir, prev.Artifact)); statErr != nil {
			return true, fmt.Sprintf("package %q artifact is missing from the output directory", name), nil
		}
	}

	// Check for any packages that have been removed from the manifest but are
	// still tracked in the cache (they'd change the index).
	manifestSources := make(map[string]bool, len(i.layout.manifest.Packages))
	for _, pkg := range i.layout.manifest.Packages {
		manifestSources[pkg.Source] = true
	}
	for source := range cache.Entries {
		if !manifestSources[source] {
			return true, fmt.Sprintf("package source %q was removed from the manifest", source), nil
		}
	}

	// No content change — but Build restamps expires (and bumps the serial)
	// when the published window is absent, unparseable, or below its half-life
	// (D13/D-C1 renewal), so status must report that as pending too. Uses the
	// default window: `repo status` has no --valid-for flag.
	if exp := publishedExpires(i.layout.outputDir); exp == "" {
		return true, "metadata expiry refresh due", nil
	} else if t, perr := time.Parse(time.RFC3339, exp); perr != nil || time.Until(t) <= DefaultValidFor/2 {
		return true, "metadata expiry refresh due", nil
	}

	return false, "", nil
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

	kp, err := LoadKey(resolveRel(insp.layout.manifestDir, insp.layout.manifest.Key.Path), password)
	if err != nil {
		return nil, &PublishError{
			Msg:  "cannot unlock signing key",
			Hint: "set POLYPKG_REPO_KEY_PASSWORD or pass --key-password-file with the correct password",
			Err:  err,
		}
	}

	return &Builder{insp: insp, key: kp}, nil
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

// guardKeyNotInOutput refuses to proceed if the secret key or build cache would
// live inside the published directory, which would expose private material.
func guardKeyNotInOutput(outputDir, keyPath, keyDir string) error {
	absOut, _ := filepath.Abs(outputDir)
	sep := string(os.PathSeparator)
	for _, p := range []string{keyPath, keyDir} {
		ap, _ := filepath.Abs(p)
		if ap == absOut || strings.HasPrefix(ap+sep, absOut+sep) {
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

	// Pool blobs are content-addressed under <output>/pool (D10).
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
		Schema:   "polypkg.index/v2",
		Packages: map[string][]schema.IndexEntry{},
	}

	// newEntries will replace cache.Entries so removed packages drop out.
	newEntries := make(map[string]CacheEntry, len(names))
	changed := false

	for _, name := range names {
		pkg := lay.manifest.Packages[name]
		srcDir := resolveRel(lay.manifestDir, pkg.Source)

		fp, err := SourceFingerprint(srcDir)
		if err != nil {
			return Result{}, &PublishError{
				Msg:  fmt.Sprintf("cannot fingerprint package %q source", name),
				Hint: fmt.Sprintf("check that packages.%s.source (%s) exists and is readable", name, pkg.Source),
				Err:  err,
			}
		}

		// Cache hit: fingerprint unchanged and artifact file still present.
		if prev, ok := cache.Get(pkg.Source); ok && prev.Fingerprint == fp {
			artPath := filepath.Join(lay.outputDir, prev.Artifact)
			if _, statErr := os.Stat(artPath); statErr == nil {
				// Reuse the cached attestation refs verbatim (nil covers entries
				// built under --skip-attestations). CAVEAT: a cache hit reuses the
				// attestation decision the entry was built with — flipping
				// SkipAttestations takes effect only after a source change or a
				// cache clear (documented in the --skip-attestations help text).
				idx.Packages[name] = []schema.IndexEntry{{
					Version:      prev.Version,
					ContentHash:  prev.ContentHash,
					Artifact:     prev.Artifact,
					Revision:     prev.Revision,
					Attestations: prev.Attestations,
					Depends:      prev.Depends,
					Recommends:   prev.Recommends,
					Suggests:     prev.Suggests,
					Provides:     prev.Provides,
					Conflicts:    prev.Conflicts,
					Obsoletes:    prev.Obsoletes,
				}}
				newEntries[pkg.Source] = prev
				continue
			}
		}

		// (Re)build the package.
		artifact, pkgParsed, err := PackArtifact(srcDir)
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

		version := pkgParsed.Version
		ch := ContentHash(artifact)
		// Content-addressed pool naming (D10): the blob path is derived from
		// the artifact's own hash, so a republish of the same version writes a
		// NEW blob and old blobs persist immutably (rollback keeps resolving).
		artName := "pool/" + strings.TrimPrefix(ch, "blake3:") + ".tar.zst"
		artPath := filepath.Join(lay.outputDir, artName)
		sigPath := artPath + ".minisig"

		// Informational revision ordinal (D10): counts republishes of the same
		// version with different content; resets to 1 on a version change. When
		// the cache has no entry for this version (lost/cold cache) the
		// published index is the floor: same content hash → keep the published
		// ordinal, different hash → published+1. Without the floor a cache loss
		// would restart a republished version's ordinal at 1.
		revision := 1
		if prev, ok := cache.Get(pkg.Source); ok && prev.Version == version {
			if prev.ContentHash == ch {
				revision = prev.Revision
			} else {
				revision = prev.Revision + 1
			}
		} else if pubIdx != nil {
			for i := range pubIdx.Packages[name] {
				pe := &pubIdx.Packages[name][i]
				if pe.Version != version {
					continue
				}
				if pe.ContentHash == ch {
					revision = pe.Revision
				} else {
					revision = pe.Revision + 1
				}
				break
			}
		}

		// Per-package lint attestation (D6/D7): re-run the pkglint engine for
		// the authoritative predicate, refuse error-severity packages (D-C4),
		// and sign the canonical in-toto Statement. The subject NAME is the
		// human <name>-<version>.tar.zst — informational, the digest is the
		// binding — so the published bytes are byte-identical to `pkg build`'s
		// unsigned preview (D12). Lint runs BEFORE any pool write so a refused
		// package publishes nothing; the att pool writes land with the artifact
		// writes, ahead of the index/trust metadata batch (D16).
		var attRefs []schema.AttestationRef
		var attName, attCH string
		var attBytes []byte
		if !opts.SkipAttestations {
			lintRes, lerr := pkglint.Lint(srcDir)
			if lerr != nil {
				return Result{}, &PublishError{Msg: fmt.Sprintf("cannot lint package %q", name), Err: lerr}
			}
			if lintRes.HasErrors() {
				return Result{}, &PublishError{
					Msg:  fmt.Sprintf("package %q has error-severity lint findings; refusing to publish", name),
					Hint: "run `polypkg pkg lint " + pkg.Source + "` and fix every error finding",
				}
			}
			sarifBytes, serr := pkglint.SARIF(lintRes)
			if serr != nil {
				return Result{}, fmt.Errorf("render SARIF for %q: %w", name, serr)
			}
			st := attest.AssembleStatement(
				fmt.Sprintf("%s-%s.tar.zst", name, version),
				strings.TrimPrefix(ch, "blake3:"),
				json.RawMessage(sarifBytes))
			var aerr error
			attBytes, aerr = st.CanonicalJSON()
			if aerr != nil {
				return Result{}, fmt.Errorf("canonicalize attestation for %q: %w", name, aerr)
			}
			attCH = ContentHash(attBytes)
			attName = "pool/" + strings.TrimPrefix(attCH, "blake3:") + ".att.json"
			attRefs = []schema.AttestationRef{{
				PredicateType: attest.PredicateTypeSARIF,
				Artifact:      attName,
				ContentHash:   attCH,
				Kind:          schema.KindNativeJCS,
				Format:        schema.FormatPolypkgSARIF,
			}}
		}

		if err := writeAtomic(artPath, artifact); err != nil {
			return Result{}, &PublishError{Msg: fmt.Sprintf("write artifact %s", artName), Err: err}
		}
		sig := b.key.SignArtifact(name, version, artifact)
		if err := writeAtomic(sigPath, []byte(sig)); err != nil {
			return Result{}, &PublishError{Msg: fmt.Sprintf("write artifact signature %s.minisig", artName), Err: err}
		}
		if !opts.SkipAttestations {
			if err := writeAtomic(filepath.Join(lay.outputDir, attName), attBytes); err != nil {
				return Result{}, &PublishError{Msg: fmt.Sprintf("write attestation %s", attName), Err: err}
			}
			attSig := b.key.SignAttestation(name, version, attBytes)
			if err := writeAtomic(filepath.Join(lay.outputDir, attName+".minisig"), []byte(attSig)); err != nil {
				return Result{}, &PublishError{Msg: fmt.Sprintf("write attestation signature %s.minisig", attName), Err: err}
			}
		}

		// Carried external provenance (2b): discover attestations/*.json in the
		// package source, bind each against the packed bytes (pack-time half of
		// the two-point binding, P6), store verbatim in the pool with a publisher
		// transport signature, and emit a polypkg link attestation binding the
		// artifact to the covered materials. Skipped under --skip-attestations
		// (which suppresses all attestation work).
		if !opts.SkipAttestations {
			carriedFiles, derr := discoverCarried(srcDir)
			if derr != nil {
				return Result{}, &PublishError{Msg: fmt.Sprintf("discover carried attestations for %q", name), Err: derr}
			}
			var linkMaterials []attest.LinkMaterial
			for _, cf := range carriedFiles {
				cbytes, rerr := os.ReadFile(cf) //nolint:gosec // G304: cf is under the operator's package source attestations/ dir
				if rerr != nil {
					return Result{}, &PublishError{Msg: fmt.Sprintf("read carried attestation %s", filepath.Base(cf)), Err: rerr}
				}
				bind, berr := bindCarried(srcDir, artifact, cbytes)
				if berr != nil {
					return Result{}, &PublishError{
						Msg:  fmt.Sprintf("carried attestation %s for package %q", filepath.Base(cf), name),
						Hint: "the carried provenance must describe the packed artifact or a content file (matched by digest)",
						Err:  berr,
					}
				}
				cCH := ContentHash(cbytes)
				cName := "pool/" + strings.TrimPrefix(cCH, "blake3:") + ".att.json"
				if werr := writeAtomic(filepath.Join(lay.outputDir, cName), cbytes); werr != nil {
					return Result{}, &PublishError{Msg: fmt.Sprintf("write carried attestation %s", cName), Err: werr}
				}
				cSig := b.key.SignAttestation(name, version, cbytes)
				if werr := writeAtomic(filepath.Join(lay.outputDir, cName+".minisig"), []byte(cSig)); werr != nil {
					return Result{}, &PublishError{Msg: fmt.Sprintf("write carried attestation signature %s.minisig", cName), Err: werr}
				}
				attRefs = append(attRefs, schema.AttestationRef{
					PredicateType:  bind.PredicateType,
					Artifact:       cName,
					ContentHash:    cCH,
					Kind:           schema.KindCarriedOpaque,
					Format:         bind.Format,
					SubjectScope:   bind.SubjectScope,
					SubjectDigests: bind.SubjectDigests,
				})
				linkMaterials = append(linkMaterials, bind.Materials...)
			}
			if len(linkMaterials) > 0 {
				linkSt, lerr := attest.AssembleLinkStatement(
					fmt.Sprintf("%s-%s.tar.zst", name, version),
					strings.TrimPrefix(ch, "blake3:"), linkMaterials)
				if lerr != nil {
					return Result{}, fmt.Errorf("assemble link attestation for %q: %w", name, lerr)
				}
				linkBytes, lerr := linkSt.CanonicalJSON()
				if lerr != nil {
					return Result{}, fmt.Errorf("canonicalize link attestation for %q: %w", name, lerr)
				}
				linkCH := ContentHash(linkBytes)
				linkName := "pool/" + strings.TrimPrefix(linkCH, "blake3:") + ".att.json"
				if werr := writeAtomic(filepath.Join(lay.outputDir, linkName), linkBytes); werr != nil {
					return Result{}, &PublishError{Msg: fmt.Sprintf("write link attestation %s", linkName), Err: werr}
				}
				linkSig := b.key.SignAttestation(name, version, linkBytes)
				if werr := writeAtomic(filepath.Join(lay.outputDir, linkName+".minisig"), []byte(linkSig)); werr != nil {
					return Result{}, &PublishError{Msg: fmt.Sprintf("write link attestation signature %s.minisig", linkName), Err: werr}
				}
				attRefs = append(attRefs, schema.AttestationRef{
					PredicateType: attest.PredicateTypePolypkgLink,
					Artifact:      linkName,
					ContentHash:   linkCH,
					Kind:          schema.KindNativeJCS,
					Format:        schema.FormatPolypkgLink,
					SubjectScope:  "artifact",
				})
			}
			// Stable order so a no-op rebuild stays byte-identical (D13).
			sort.SliceStable(attRefs, func(i, j int) bool { return attRefLess(attRefs[i], attRefs[j]) })
		}

		idx.Packages[name] = []schema.IndexEntry{{
			Version:      version,
			ContentHash:  ch,
			Artifact:     artName,
			Revision:     revision,
			Attestations: attRefs,
			Depends:      pkgParsed.Depends,
			Recommends:   pkgParsed.Recommends,
			Suggests:     pkgParsed.Suggests,
			Provides:     pkgParsed.Provides,
			Conflicts:    pkgParsed.Conflicts,
			Obsoletes:    pkgParsed.Obsoletes,
		}}
		ce := CacheEntry{
			Fingerprint: fp,
			ContentHash: ch,
			Artifact:    artName,
			Version:     version,
			Revision:    revision,
			Depends:     pkgParsed.Depends,
			Recommends:  pkgParsed.Recommends,
			Suggests:    pkgParsed.Suggests,
			Provides:    pkgParsed.Provides,
			Conflicts:   pkgParsed.Conflicts,
			Obsoletes:   pkgParsed.Obsoletes,
		}
		ce.Attestations = attRefs
		newEntries[pkg.Source] = ce
		changed = true
	}

	// Stamp the freshness bound (D13). computeExpires reuses the published
	// expiry on a pure no-op rebuild so the byte-compare below still sees
	// identical index bytes (serial-stable); a content change or a window past
	// its half-life restamps, and the byte-compare then bumps the serial —
	// TUF-style re-signing.
	expires := computeExpires(lay.outputDir, changed, opts.ValidFor)
	idx.Expires = expires

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
	serial := before
	idxPath := filepath.Join(lay.outputDir, "index.json")
	trustRootPubPath := filepath.Join(lay.outputDir, "trust_root.pub")
	currentPubFile := []byte(b.key.PublicKeyFile("polypkg " + lay.manifest.Source + " trust root"))
	if before == 0 || changed || !fileHasContent(idxPath, idxJSON) || !fileHasContent(trustRootPubPath, currentPubFile) {
		changed = true
		serial = before + 1
	}

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
		if err := writeAtomicBatch([]publishFile{
			{path: filepath.Join(lay.outputDir, "index.json"), body: idxJSON},
			{path: filepath.Join(lay.outputDir, "index.json.minisig"), body: []byte(idxSig)},
			{path: filepath.Join(lay.outputDir, "trust.json"), body: trustJSON},
			{path: filepath.Join(lay.outputDir, "trust.json.minisig"), body: []byte(trustSig)},
			{path: filepath.Join(lay.outputDir, "trust_root.pub"), body: []byte(pubKey)},
		}); err != nil {
			return Result{}, &PublishError{Msg: "publish repository metadata", Err: err}
		}
	}

	// Persist updated cache (removed packages drop out via newEntries replacement).
	cache.Serial = serial
	cache.Entries = newEntries
	if err := cache.Save(lay.cachePath); err != nil {
		return Result{}, fmt.Errorf("save build cache: %w", err)
	}

	return Result{Changed: changed, SerialBefore: before, SerialAfter: serial}, nil
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

// computeExpires returns the RFC3339 expiry for this publish. It reuses the
// currently published expiry when nothing changed and more than half the
// validity window remains, so no-op rebuilds stay byte-identical (and
// serial-stable); otherwise it stamps a fresh now+validFor (D13/D-C1).
func computeExpires(outputDir string, contentChanged bool, validFor time.Duration) string {
	if !contentChanged {
		if cur := publishedExpires(outputDir); cur != "" {
			if t, err := time.Parse(time.RFC3339, cur); err == nil {
				if time.Until(t) > validFor/2 {
					return cur
				}
			}
		}
	}
	return time.Now().UTC().Add(validFor).Format(time.RFC3339)
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
