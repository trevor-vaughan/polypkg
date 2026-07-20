package repo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/pkglint"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// poolBlob is one attestation document to publish alongside an artifact: its
// pool-relative name ("pool/<hash>.att.json") and canonical bytes. Its transport
// signature is produced at emit time under the package's name/version.
type poolBlob struct {
	name  string
	bytes []byte
}

// packageWork is the fully-resolved output for one package, independent of
// whether it came from a source tree or a pre-built ingest. emitPackage consumes
// it to publish the pool blobs and produce the index and cache entries.
type packageWork struct {
	name        string
	version     string
	contentHash string // "blake3:…" of the artifact
	artifact    []byte
	fingerprint string // cache freshness token: SourceFingerprint (source) or contentHash (prebuilt)
	cacheKey    string // build-cache map key: pkg.Source (source) or contentHash (prebuilt)
	attRefs     []schema.AttestationRef
	attBlobs    []poolBlob
	pkg         *schema.Package
}

// nextRevision computes the informational republish ordinal for version/ch,
// using the build-cache entry (by cacheKey) as the primary source and the
// published index as the cold-cache floor.
func nextRevision(cache *BuildCache, pubIdx *schema.Index, cacheKey, name, version, ch string) int {
	revision := 1
	if prev, ok := cache.Get(cacheKey); ok && prev.Version == version {
		if prev.ContentHash == ch {
			return prev.Revision
		}
		return prev.Revision + 1
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
	return revision
}

// carriedDoc is one carried attestation envelope with its source basename (for
// operator-facing errors) and bytes.
type carriedDoc struct {
	name  string
	bytes []byte
}

// bindCarriedSet binds every carried attestation envelope against the artifact
// and the content targets rooted at bindDir (reusing bindCarried), then folds in
// the polypkg link attestation covering the bound materials. Returns the carried
// + link AttestationRefs and the pool blobs to publish in carried-discovery order
// (the link attestation last); it does NOT sort — the CALLER sorts refs for the
// published index. Fail-closed: an envelope binding nothing errs. Shared by the
// source and prebuilt paths so both bind identically.
func bindCarriedSet(bindDir, name, version, ch string, artifact []byte, carried []carriedDoc) ([]schema.AttestationRef, []poolBlob, error) {
	var refs []schema.AttestationRef
	var blobs []poolBlob
	var linkMaterials []attest.LinkMaterial
	for _, cd := range carried {
		bind, berr := bindCarried(bindDir, artifact, cd.bytes)
		if berr != nil {
			return nil, nil, &PublishError{
				Msg:  fmt.Sprintf("carried attestation %s for package %q", cd.name, name),
				Hint: "the carried provenance must describe the packed artifact or a content file (matched by digest)",
				Err:  berr,
			}
		}
		cCH := ContentHash(cd.bytes)
		cName := "pool/" + strings.TrimPrefix(cCH, "blake3:") + ".att.json"
		blobs = append(blobs, poolBlob{name: cName, bytes: cd.bytes})
		refs = append(refs, schema.AttestationRef{
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
			return nil, nil, fmt.Errorf("assemble link attestation for %q: %w", name, lerr)
		}
		linkBytes, lerr := linkSt.CanonicalJSON()
		if lerr != nil {
			return nil, nil, fmt.Errorf("canonicalize link attestation for %q: %w", name, lerr)
		}
		linkCH := ContentHash(linkBytes)
		linkName := "pool/" + strings.TrimPrefix(linkCH, "blake3:") + ".att.json"
		blobs = append(blobs, poolBlob{name: linkName, bytes: linkBytes})
		refs = append(refs, schema.AttestationRef{
			PredicateType: attest.PredicateTypePolypkgLink,
			Artifact:      linkName,
			ContentHash:   linkCH,
			Kind:          schema.KindNativeJCS,
			Format:        schema.FormatPolypkgLink,
			SubjectScope:  "artifact",
		})
	}
	return refs, blobs, nil
}

// sourceAttestations assembles the attestation work for a SOURCE-built package:
// the native pkglint SARIF attestation (refused on error-severity findings) plus
// every carried attestation discovered under srcDir/attestations, each bound
// against srcDir's content tree. Returns the refs and the pool blobs, stably
// sorted. skip short-circuits to no attestations (--skip-attestations).
func (b *Builder) sourceAttestations(srcDir, srcRel, name, version, ch string, artifact []byte, skip bool) ([]schema.AttestationRef, []poolBlob, error) {
	if skip {
		return nil, nil, nil
	}
	var refs []schema.AttestationRef
	var blobs []poolBlob

	lintRes, lerr := pkglint.Lint(srcDir)
	if lerr != nil {
		return nil, nil, &PublishError{Msg: fmt.Sprintf("cannot lint package %q", name), Err: lerr}
	}
	if lintRes.HasErrors() {
		return nil, nil, &PublishError{
			Msg:  fmt.Sprintf("package %q has error-severity lint findings; refusing to publish", name),
			Hint: "run `polypkg pkg lint " + srcRel + "` and fix every error finding",
		}
	}
	sarifBytes, serr := pkglint.SARIF(lintRes)
	if serr != nil {
		return nil, nil, fmt.Errorf("render SARIF for %q: %w", name, serr)
	}
	st := attest.AssembleStatement(
		fmt.Sprintf("%s-%s.tar.zst", name, version),
		strings.TrimPrefix(ch, "blake3:"), json.RawMessage(sarifBytes))
	attBytes, aerr := st.CanonicalJSON()
	if aerr != nil {
		return nil, nil, fmt.Errorf("canonicalize attestation for %q: %w", name, aerr)
	}
	attCH := ContentHash(attBytes)
	attName := "pool/" + strings.TrimPrefix(attCH, "blake3:") + ".att.json"
	refs = append(refs, schema.AttestationRef{
		PredicateType: attest.PredicateTypeSARIF,
		Artifact:      attName,
		ContentHash:   attCH,
		Kind:          schema.KindNativeJCS,
		Format:        schema.FormatPolypkgSARIF,
	})
	blobs = append(blobs, poolBlob{name: attName, bytes: attBytes})

	carriedFiles, derr := discoverCarried(srcDir)
	if derr != nil {
		return nil, nil, &PublishError{Msg: fmt.Sprintf("discover carried attestations for %q", name), Err: derr}
	}
	carried, rerr := readCarriedFiles(carriedFiles)
	if rerr != nil {
		return nil, nil, rerr
	}
	cRefs, cBlobs, berr := bindCarriedSet(srcDir, name, version, ch, artifact, carried)
	if berr != nil {
		return nil, nil, berr
	}
	refs = append(refs, cRefs...)
	blobs = append(blobs, cBlobs...)
	sort.SliceStable(refs, func(i, j int) bool { return attRefLess(refs[i], refs[j]) })
	return refs, blobs, nil
}

// prebuiltAttestations assembles the attestation work for an INGESTED package:
// carried-only, bound against the extracted tree at scratchDir. No native lint —
// a prebuilt package has no source tree, and it carries the upstream's
// attestations verbatim (re-bound). attDir holds the staged *.json blobs (same
// discovery rule as a source attestations/ dir: top-level *.json).
func (b *Builder) prebuiltAttestations(scratchDir, attDir, name, version, ch string, artifact []byte) ([]schema.AttestationRef, []poolBlob, error) {
	files, derr := discoverCarriedDir(attDir)
	if derr != nil {
		return nil, nil, &PublishError{Msg: fmt.Sprintf("discover prebuilt attestations for %q", name), Err: derr}
	}
	carried, rerr := readCarriedFiles(files)
	if rerr != nil {
		return nil, nil, rerr
	}
	refs, blobs, berr := bindCarriedSet(scratchDir, name, version, ch, artifact, carried)
	if berr != nil {
		return nil, nil, berr
	}
	sort.SliceStable(refs, func(i, j int) bool { return attRefLess(refs[i], refs[j]) })
	return refs, blobs, nil
}

// emitPackage writes one package's artifact, its signature, and every
// attestation pool blob (each transport-signed under name/version), then returns
// the index and cache entries. Shared author pass for source-build and
// pre-built-ingest paths. outputDir is the repo output root.
func (b *Builder) emitPackage(outputDir string, w packageWork, revision int) (schema.IndexEntry, CacheEntry, error) {
	artName := "pool/" + strings.TrimPrefix(w.contentHash, "blake3:") + ".tar.zst"
	artPath := filepath.Join(outputDir, artName)
	if err := writeAtomic(artPath, w.artifact); err != nil {
		return schema.IndexEntry{}, CacheEntry{}, &PublishError{Msg: fmt.Sprintf("write artifact %s", artName), Err: err}
	}
	sig := b.key.SignArtifact(w.name, w.version, w.artifact)
	if err := writeAtomic(artPath+".minisig", []byte(sig)); err != nil {
		return schema.IndexEntry{}, CacheEntry{}, &PublishError{Msg: fmt.Sprintf("write artifact signature %s.minisig", artName), Err: err}
	}
	for _, blob := range w.attBlobs {
		if err := writeAtomic(filepath.Join(outputDir, blob.name), blob.bytes); err != nil {
			return schema.IndexEntry{}, CacheEntry{}, &PublishError{Msg: fmt.Sprintf("write attestation %s", blob.name), Err: err}
		}
		bs := b.key.SignAttestation(w.name, w.version, blob.bytes)
		if err := writeAtomic(filepath.Join(outputDir, blob.name+".minisig"), []byte(bs)); err != nil {
			return schema.IndexEntry{}, CacheEntry{}, &PublishError{Msg: fmt.Sprintf("write attestation signature %s.minisig", blob.name), Err: err}
		}
	}
	entry := schema.IndexEntry{
		Version:      w.version,
		ContentHash:  w.contentHash,
		Artifact:     artName,
		Revision:     revision,
		Attestations: w.attRefs,
		Depends:      w.pkg.Depends,
		Recommends:   w.pkg.Recommends,
		Suggests:     w.pkg.Suggests,
		Provides:     w.pkg.Provides,
		Conflicts:    w.pkg.Conflicts,
		Obsoletes:    w.pkg.Obsoletes,
	}
	ce := CacheEntry{
		Fingerprint: w.fingerprint,
		ContentHash: w.contentHash,
		Artifact:    artName,
		Version:     w.version,
		Revision:    revision,
		Depends:     w.pkg.Depends,
		Recommends:  w.pkg.Recommends,
		Suggests:    w.pkg.Suggests,
		Provides:    w.pkg.Provides,
		Conflicts:   w.pkg.Conflicts,
		Obsoletes:   w.pkg.Obsoletes,
	}
	ce.Attestations = w.attRefs
	return entry, ce, nil
}

// readCarriedFiles reads each carried attestation file into memory, preserving
// order. Shared by the source path (files on disk) and the prebuilt path (a
// staged attestations dir).
func readCarriedFiles(paths []string) ([]carriedDoc, error) {
	var out []carriedDoc
	for _, p := range paths {
		b, err := os.ReadFile(p) //nolint:gosec // G304: p is under the operator's staged attestations dir
		if err != nil {
			return nil, &PublishError{Msg: fmt.Sprintf("read carried attestation %s", filepath.Base(p)), Err: err}
		}
		out = append(out, carriedDoc{name: filepath.Base(p), bytes: b})
	}
	return out, nil
}
