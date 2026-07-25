package repo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/gowebpki/jcs"
	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/source"
)

// ingestHit carries a prebuilt cache-hit's reusable index and cache entries so
// the build loop can short-circuit without re-extracting the fetched tar.
type ingestHit struct {
	reuse      bool
	entry      schema.IndexEntry
	cacheEntry CacheEntry
}

// ingestPackage prepares a pre-built package for emission: it reads the fetched
// .tar.zst, cache-keys it on the artifact content-hash (a hit short-circuits),
// extracts the tar into a scratch dir under the confinement guards of
// source.ExtractTarZst, parses the inner polypkg.yaml, and RE-BINDS every carried
// attestation against the extracted bytes (independent proof of the P6
// two-point binding). It never runs pkglint — a prebuilt package carries the
// upstream's attestations verbatim; there is no source tree to lint.
func (b *Builder) ingestPackage(lay repoLayout, name string, pb *schema.RepoPrebuilt, cache *BuildCache) (packageWork, ingestHit, error) {
	artPath := resolveRel(lay.manifestDir, pb.Artifact)
	artifact, err := os.ReadFile(artPath) //nolint:gosec // G304: artPath is the operator-declared prebuilt artifact
	if err != nil {
		return packageWork{}, ingestHit{}, &PublishError{
			Msg:  fmt.Sprintf("cannot read prebuilt artifact for %q", name),
			Hint: fmt.Sprintf("check packages.%s.prebuilt.artifact (%s)", name, pb.Artifact),
			Err:  err,
		}
	}
	ch := ContentHash(artifact)

	// Cache hit: same fetched bytes, artifact still in the pool → reuse verbatim.
	if prev, ok := cache.Get(ch); ok && prev.Fingerprint == ch {
		if _, statErr := os.Stat(filepath.Join(lay.outputDir, prev.Artifact)); statErr == nil {
			return packageWork{cacheKey: ch, version: prev.Version, contentHash: ch},
				ingestHit{reuse: true, entry: prev.indexEntry(), cacheEntry: prev}, nil
		}
	}

	// Extract into a scratch dir so the extracted tree (polypkg.yaml + content/**)
	// serves both as the parse source and the binding target set. MkdirTemp lives
	// under the OS temp root, outside the served output dir.
	scratch, err := os.MkdirTemp("", "polypkg-ingest-*")
	if err != nil {
		return packageWork{}, ingestHit{}, fmt.Errorf("create ingest scratch dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	if err := source.ExtractTarZst(bytes.NewReader(artifact), scratch); err != nil {
		return packageWork{}, ingestHit{}, &PublishError{
			Msg:  fmt.Sprintf("cannot extract prebuilt artifact for %q", name),
			Hint: "the prebuilt artifact must be a polypkg .tar.zst (polypkg.yaml + content/**)",
			Err:  err,
		}
	}

	pkgParsed, err := ReadPackageSource(scratch)
	if err != nil {
		return packageWork{}, ingestHit{}, &PublishError{
			Msg: fmt.Sprintf("prebuilt artifact for %q has no valid polypkg.yaml", name), Err: err,
		}
	}
	if pkgParsed.Name != name {
		return packageWork{}, ingestHit{}, &PublishError{
			Msg:  fmt.Sprintf("manifest key %q does not match prebuilt package name %q", name, pkgParsed.Name),
			Hint: "the key in packages.<name> must match the name field in the fetched package's polypkg.yaml",
		}
	}

	refs, blobs, err := b.prebuiltAttestations(scratch, resolveRel(lay.manifestDir, pb.Attestations), name, pkgParsed.Version, ch, artifact)
	if err != nil {
		return packageWork{}, ingestHit{}, err
	}
	if pb.NativeAttestation != "" {
		nref, nblob, nerr := b.nativeAttestationRef(resolveRel(lay.manifestDir, pb.NativeAttestation), name, pkgParsed.Version, ch)
		if nerr != nil {
			return packageWork{}, ingestHit{}, nerr
		}
		refs = append(refs, nref)
		blobs = append(blobs, nblob)
		sort.SliceStable(refs, func(i, j int) bool { return attRefLess(refs[i], refs[j]) })
	}
	return packageWork{
		name: name, version: pkgParsed.Version, contentHash: ch, artifact: artifact,
		fingerprint: ch, cacheKey: ch, attRefs: refs, attBlobs: blobs, pkg: pkgParsed,
	}, ingestHit{}, nil
}

// mergeCarriedBundle folds one staged upstream trust bundle into the running
// merge sets. Builder keys dedup by key_id: an identical repeat is idempotent, a
// conflicting repeat (same id, different material) is fail-closed. Sigstore roots
// are appended, deduped by exact structural equality.
func mergeCarriedBundle(path string, keys map[string]schema.BuilderKey, order *[]string, roots *[]schema.SigstoreRoot) error {
	f, err := os.Open(path) //nolint:gosec // G304: path is the operator-declared prebuilt.trust_bundle
	if err != nil {
		return &PublishError{Msg: "cannot open carried trust bundle", Hint: "check packages.<name>.prebuilt.trust_bundle", Err: err}
	}
	defer func() { _ = f.Close() }()
	tb, err := schema.ParseTrustBundle(f)
	if err != nil {
		return &PublishError{Msg: fmt.Sprintf("carried trust bundle %s is invalid", filepath.Base(path)), Err: err}
	}
	for i := range tb.BuilderKeys {
		k := tb.BuilderKeys[i]
		if prev, ok := keys[k.KeyID]; ok {
			if prev != k {
				return &PublishError{
					Msg:  fmt.Sprintf("carried trust bundles disagree on builder key_id %q", k.KeyID),
					Hint: "two upstream bundles vouch for the same key id with differing material (key, algo, or validity window); refusing to merge",
				}
			}
			continue
		}
		keys[k.KeyID] = k
		*order = append(*order, k.KeyID)
	}
	for i := range tb.SigstoreRoots {
		if !containsRoot(*roots, tb.SigstoreRoots[i]) {
			*roots = append(*roots, tb.SigstoreRoots[i])
		}
	}
	return nil
}

// containsRoot reports whether roots already holds a structurally-equal root.
func containsRoot(roots []schema.SigstoreRoot, r schema.SigstoreRoot) bool {
	for i := range roots {
		if sigstoreRootEqual(roots[i], r) {
			return true
		}
	}
	return false
}

func sigstoreRootEqual(a, b schema.SigstoreRoot) bool {
	return a.ValidFrom == b.ValidFrom && a.ValidUntil == b.ValidUntil &&
		slices.Equal(a.FulcioCA, b.FulcioCA) && slices.Equal(a.RekorKeys, b.RekorKeys) && slices.Equal(a.CTLogKeys, b.CTLogKeys)
}

// buildCarriedBundle assembles the merged repo-level trust bundle (builder keys
// in first-seen order, roots as merged), stamped with the LOCAL source and the
// repo serial/expires. Returns nil when nothing was carried.
func buildCarriedBundle(localSource string, serial uint64, expires string, keys map[string]schema.BuilderKey, order []string, roots []schema.SigstoreRoot) *schema.TrustBundle {
	if len(order) == 0 && len(roots) == 0 {
		return nil
	}
	bk := make([]schema.BuilderKey, 0, len(order))
	for _, id := range order {
		bk = append(bk, keys[id])
	}
	return &schema.TrustBundle{
		Schema:        "polypkg.trust-bundle/v1",
		Source:        localSource,
		Serial:        serial,
		IssuedAt:      buildTimestamp,
		Expires:       expires,
		BuilderKeys:   bk,
		SigstoreRoots: roots,
	}
}

// publishedBundleMatches reports whether the currently published trust-bundle.json
// already carries exactly the merged builder keys (by full material — id, key,
// algo, validity) and sigstore roots (serial and expires excluded — derived, like
// the index compare). Folds carry-forward into the changed-decision so a no-op
// rebuild stays serial-stable but any change in carried material bumps the serial.
func publishedBundleMatches(outputDir string, keys map[string]schema.BuilderKey, roots []schema.SigstoreRoot) bool {
	raw, err := os.ReadFile(filepath.Join(outputDir, "trust-bundle.json")) //nolint:gosec // G304: our own prior published doc
	if err != nil {
		return false
	}
	var tb schema.TrustBundle
	if err := json.Unmarshal(raw, &tb); err != nil {
		return false
	}
	if len(tb.BuilderKeys) != len(keys) {
		return false
	}
	for i := range tb.BuilderKeys {
		want, ok := keys[tb.BuilderKeys[i].KeyID]
		if !ok || want != tb.BuilderKeys[i] {
			return false
		}
	}
	if len(tb.SigstoreRoots) != len(roots) {
		return false
	}
	for i := range roots {
		if !containsRoot(tb.SigstoreRoots, roots[i]) {
			return false
		}
	}
	return true
}

// nativeAttestationRef reads a publisher-supplied native SARIF attestation preview,
// validates it is a JCS-canonical in-toto SARIF statement whose subject binds the
// artifact content-hash, and returns the AttestationRef + pool blob to sign and publish
// VERBATIM (Phase C: the signed attestation is byte-identical to the publisher's preview).
func (b *Builder) nativeAttestationRef(path, name, version, ch string) (schema.AttestationRef, poolBlob, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: operator-declared prebuilt.native_attestation
	if err != nil {
		return schema.AttestationRef{}, poolBlob{}, &PublishError{
			Msg:  fmt.Sprintf("cannot read native attestation for %q", name),
			Hint: fmt.Sprintf("check packages.%s.prebuilt.native_attestation (%s)", name, path), Err: err}
	}
	st, err := attest.ParseStatement(data)
	if err != nil {
		return schema.AttestationRef{}, poolBlob{}, &PublishError{
			Msg: fmt.Sprintf("native attestation for %q is not a valid in-toto statement", name), Err: err}
	}
	if st.PredicateType != attest.PredicateTypeSARIF {
		return schema.AttestationRef{}, poolBlob{}, &PublishError{
			Msg:  fmt.Sprintf("native attestation for %q has predicateType %q, want the polypkg SARIF predicate", name, st.PredicateType),
			Hint: "supply a non-SARIF document via prebuilt.attestations (carried) instead"}
	}
	wantName := fmt.Sprintf("%s-%s.tar.zst", name, version)
	wantHex := strings.TrimPrefix(ch, "blake3:")
	bound := false
	for _, s := range st.Subject {
		if s.Name == wantName && s.Digest["blake3"] == wantHex {
			bound = true
			break
		}
	}
	if !bound {
		return schema.AttestationRef{}, poolBlob{}, &PublishError{
			Msg:  fmt.Sprintf("native attestation for %q does not bind the artifact", name),
			Hint: fmt.Sprintf("its subject must be name=%s digest.blake3=%s", wantName, wantHex)}
	}
	canon, cerr := jcs.Transform(data)
	if cerr != nil || !bytes.Equal(canon, data) {
		return schema.AttestationRef{}, poolBlob{}, &PublishError{
			Msg:  fmt.Sprintf("native attestation for %q is not JCS-canonical", name),
			Hint: "publish the exact `pkg build` .att.json bytes (canonical); do not reformat"}
	}
	attCH := ContentHash(data)
	attName := "pool/" + strings.TrimPrefix(attCH, "blake3:") + ".att.json"
	return schema.AttestationRef{
		PredicateType: attest.PredicateTypeSARIF,
		Artifact:      attName,
		ContentHash:   attCH,
		Kind:          schema.KindNativeJCS,
		Format:        schema.FormatPolypkgSARIF,
	}, poolBlob{name: attName, bytes: data}, nil
}
