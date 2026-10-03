package repo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/pkglint"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// newTestRepo lays out a manifest dir with one package source and a generated,
// encrypted key in a SEPARATE keyDir (outside the repo root). Returns
// (manifestPath, keyDir).
func newTestRepo(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	keyDir := t.TempDir()
	pkgDir := filepath.Join(root, "pkgs", "hello")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writePkgSrc(t, pkgDir) // defined in pack_test.go

	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "example.key")
	if err := SaveKey(keyPath, kp, "pw", KDFScrypt); err != nil {
		t.Fatal(err)
	}
	manifest := "schema: polypkg.repo/v1\nsource: example\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    - source: ./pkgs/hello\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return mPath, keyDir
}

// readIndex parses public/index.json from pubDir via schema.ParseIndex so the
// assertion runs against the strict consumer-side parser.
func readIndex(t *testing.T, pubDir string) *schema.Index {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(pubDir, "index.json"))
	if err != nil {
		t.Fatalf("read index.json: %v", err)
	}
	idx, err := schema.ParseIndex(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse index.json: %v", err)
	}
	return idx
}

// mutatePkgSrc changes the package source under dir: it appends bytes to a
// content file AND bumps its mtime, so the (relpath, size, mtimeNano)
// fingerprint is guaranteed to change.
func mutatePkgSrc(t *testing.T, dir string) {
	t.Helper()
	target := filepath.Join(dir, "content", "bin", "hello")
	f, err := os.OpenFile(target, os.O_APPEND|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("echo mutated\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(target, future, future); err != nil {
		t.Fatal(err)
	}
}

func TestPoolNamingAndRepublish(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	root := filepath.Dir(mPath)
	pub := filepath.Join(root, "public")

	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	res1, err := b.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}

	idx1 := readIndex(t, pub)
	e1 := idx1.Packages["hello"][0]
	wantArt := "pool/" + strings.TrimPrefix(e1.ContentHash, "blake3:") + ".tar.zst"
	if e1.Artifact != wantArt {
		t.Fatalf("artifact = %q, want %q", e1.Artifact, wantArt)
	}
	if e1.Revision != 1 {
		t.Fatalf("revision = %d, want 1", e1.Revision)
	}
	if _, err := os.Stat(filepath.Join(pub, e1.Artifact)); err != nil {
		t.Fatalf("pool blob missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(pub, e1.Artifact+".minisig")); err != nil {
		t.Fatalf("pool blob sig missing: %v", err)
	}

	// Republish the SAME version with different content: new blob, old persists,
	// revision increments, index repoints, serial bumps by exactly one.
	mutatePkgSrc(t, filepath.Join(root, "pkgs", "hello"))
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	res2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	idx2 := readIndex(t, pub)
	e2 := idx2.Packages["hello"][0]
	if e2.ContentHash == e1.ContentHash {
		t.Fatal("content hash did not change after source mutation")
	}
	if e2.Version != e1.Version {
		t.Fatalf("version changed unexpectedly: %s -> %s", e1.Version, e2.Version)
	}
	if e2.Revision != 2 {
		t.Fatalf("revision = %d, want 2", e2.Revision)
	}
	if _, err := os.Stat(filepath.Join(pub, e1.Artifact)); err != nil {
		t.Fatalf("old pool blob was removed (must persist immutably): %v", err)
	}
	if _, err := os.Stat(filepath.Join(pub, e2.Artifact)); err != nil {
		t.Fatalf("new pool blob missing: %v", err)
	}
	if res2.SerialAfter != res1.SerialAfter+1 {
		t.Fatalf("serial after republish = %d, want %d", res2.SerialAfter, res1.SerialAfter+1)
	}
}

// mustCanonicalStatement independently reassembles the canonical attestation
// bytes for the hello fixture entry: the subject NAME is the HUMAN
// <name>-<version>.tar.zst (informational; the digest is the binding), so the
// published attestation is byte-identical to `pkg build`'s unsigned preview
// (D12 cross-phase reproducibility).
func mustCanonicalStatement(t *testing.T, e schema.IndexEntry, sarif []byte) []byte {
	t.Helper()
	st := attest.AssembleStatement(
		fmt.Sprintf("%s-%s.tar.zst", "hello", e.Version),
		strings.TrimPrefix(e.ContentHash, "blake3:"),
		json.RawMessage(sarif))
	b, err := st.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBuildEmitsSignedAttestations(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	pub := filepath.Join(filepath.Dir(mPath), "public")
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	e := readIndex(t, pub).Packages["hello"][0]
	if len(e.Attestations) != 1 {
		t.Fatalf("attestations = %d, want 1", len(e.Attestations))
	}
	ref := e.Attestations[0]
	if ref.PredicateType != attest.PredicateTypeSARIF {
		t.Fatalf("predicate_type = %q", ref.PredicateType)
	}
	// Attestations are content-addressed under pool/ like artifact blobs.
	wantName := "pool/" + strings.TrimPrefix(ref.ContentHash, "blake3:") + ".att.json"
	if ref.Artifact != wantName {
		t.Fatalf("attestation artifact = %q, want %q", ref.Artifact, wantName)
	}
	attBytes, err := os.ReadFile(filepath.Join(pub, ref.Artifact))
	if err != nil {
		t.Fatal(err)
	}
	if ContentHash(attBytes) != ref.ContentHash {
		t.Fatal("attestation content_hash mismatch")
	}
	if _, err := os.Stat(filepath.Join(pub, ref.Artifact+".minisig")); err != nil {
		t.Fatal(err)
	}
	// Statement binds the ARTIFACT digest (bare hex == index content_hash) and
	// carries the human subject name.
	var st attest.Statement
	if err := json.Unmarshal(attBytes, &st); err != nil {
		t.Fatal(err)
	}
	if "blake3:"+st.Subject[0].Digest["blake3"] != e.ContentHash {
		t.Fatal("subject digest does not bind content_hash")
	}
	if st.Subject[0].Name != "hello-"+e.Version+".tar.zst" {
		t.Fatalf("subject name = %q, want human name", st.Subject[0].Name)
	}
	// Reproducibility: the published statement equals pkg-build's preview bytes
	// for the same source (canonical SARIF + canonical statement) — D12.
	res, err := pkglint.Lint(filepath.Join(filepath.Dir(mPath), "pkgs", "hello"))
	if err != nil {
		t.Fatal(err)
	}
	sarifBytes, err := pkglint.SARIF(res)
	if err != nil {
		t.Fatal(err)
	}
	preview := mustCanonicalStatement(t, e, sarifBytes)
	if !bytes.Equal(attBytes, preview) {
		t.Fatal("published attestation != independently reproduced bytes")
	}
}

func TestBuildSkipAttestations(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	pub := filepath.Join(filepath.Dir(mPath), "public")
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{SkipAttestations: true}); err != nil {
		t.Fatal(err)
	}
	e := readIndex(t, pub).Packages["hello"][0]
	if len(e.Attestations) != 0 {
		t.Fatalf("attestations = %d, want 0 under --skip-attestations", len(e.Attestations))
	}
	matches, err := filepath.Glob(filepath.Join(pub, "pool", "*.att.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("pool attestation files written despite --skip-attestations: %v", matches)
	}
}

// writePkgSrcWithDanglingRef writes a package source whose install action src
// references a content file that does not exist — a PKG006 error-severity
// finding. Packing still succeeds (the content tree is valid); only lint fails.
func writePkgSrcWithDanglingRef(t *testing.T, dir string) {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\n" +
		"actions:\n  - phase: post-place\n    action: install\n" +
		"    params: { src: \"$PKG/content/bin/missing\", dest: \"$ACTIVE/hello/bin/hello\" }\n"
	if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "content", "bin", "hello"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestBuildRefusesLintErrorPackage(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()
	pkgDir := filepath.Join(root, "pkgs", "hello")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writePkgSrcWithDanglingRef(t, pkgDir)

	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "example.key")
	if err := SaveKey(keyPath, kp, "pw", KDFScrypt); err != nil {
		t.Fatal(err)
	}
	manifest := "schema: polypkg.repo/v1\nsource: example\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    - source: ./pkgs/hello\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Build(BuildOptions{})
	var pe *PublishError
	if !errors.As(err, &pe) {
		t.Fatalf("want *PublishError for lint-error package, got %v", err)
	}
	if !strings.Contains(pe.Error(), "lint") || !strings.Contains(pe.Error(), "refusing") {
		t.Fatalf("error should mention lint refusal, got: %v", pe)
	}
	if !strings.Contains(pe.HintText(), "polypkg pkg lint") {
		t.Fatalf("hint should name `polypkg pkg lint`, got: %q", pe.HintText())
	}
	// Nothing may be published for a refused package (fresh repo → no index).
	if _, statErr := os.Stat(filepath.Join(root, "public", "index.json")); !os.IsNotExist(statErr) {
		t.Fatalf("index.json was published despite lint refusal: %v", statErr)
	}
	// The pool must hold zero blobs too: an index-only check would stay green
	// if a regression reordered the artifact write ahead of the lint gate,
	// leaving an orphaned pool blob. An absent pool dir is equally fine.
	entries, readErr := os.ReadDir(filepath.Join(root, "public", "pool"))
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatalf("read pool dir: %v", readErr)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, de := range entries {
			names = append(names, de.Name())
		}
		t.Fatalf("pool blobs written despite lint refusal: %v", names)
	}
}

func TestBuildCacheHitReusesAttestationRefs(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	pub := filepath.Join(filepath.Dir(mPath), "public")

	b1, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b1.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	e1 := readIndex(t, pub).Packages["hello"][0]
	if len(e1.Attestations) != 1 {
		t.Fatalf("setup: attestations = %d, want 1", len(e1.Attestations))
	}

	// Second build, no source change: cache hit must carry the SAME attestation
	// ref without re-linting (the index stays byte-identical → no-op).
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	res2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Changed {
		t.Fatal("expected no-op second build (cache hit)")
	}
	e2 := readIndex(t, pub).Packages["hello"][0]
	// AttestationRef now carries a SubjectDigests map (non-comparable with ==),
	// so compare structurally.
	if len(e2.Attestations) != 1 || !reflect.DeepEqual(e2.Attestations[0], e1.Attestations[0]) {
		t.Fatalf("cache-hit attestation refs differ:\n first: %+v\nsecond: %+v", e1.Attestations, e2.Attestations)
	}
}

// TestBuildCacheHitKeepsSkipDecisionUntilSourceChanges pins the documented
// caveat on BuildOptions.SkipAttestations: a cache hit reuses the attestation
// decision the entry was built with, so flipping the flag back on takes effect
// only once the package source changes and the entry is rebuilt.
func TestBuildCacheHitKeepsSkipDecisionUntilSourceChanges(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	root := filepath.Dir(mPath)
	pub := filepath.Join(root, "public")

	// First build with attestations skipped: entry carries none.
	b1, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b1.Build(BuildOptions{SkipAttestations: true}); err != nil {
		t.Fatal(err)
	}
	e1 := readIndex(t, pub).Packages["hello"][0]
	if len(e1.Attestations) != 0 {
		t.Fatalf("setup: attestations = %d, want 0 under --skip-attestations", len(e1.Attestations))
	}

	// Second build with attestations ENABLED but no source change: cache hit
	// keeps the skip-time decision — the entry still has no attestations.
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	res2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Changed {
		t.Fatal("expected no-op second build (cache hit)")
	}
	e2 := readIndex(t, pub).Packages["hello"][0]
	if len(e2.Attestations) != 0 {
		t.Fatalf("cache hit must reuse the skip decision: attestations = %d, want 0", len(e2.Attestations))
	}

	// Mutate the source: the rebuild honors the current (enabled) flag and the
	// entry now carries an attestation ref.
	mutatePkgSrc(t, filepath.Join(root, "pkgs", "hello"))
	b3, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	res3, err := b3.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res3.Changed {
		t.Fatal("expected rebuild after source mutation")
	}
	e3 := readIndex(t, pub).Packages["hello"][0]
	if len(e3.Attestations) != 1 {
		t.Fatalf("rebuilt entry: attestations = %d, want 1", len(e3.Attestations))
	}
	if _, err := os.Stat(filepath.Join(pub, e3.Attestations[0].Artifact)); err != nil {
		t.Fatalf("rebuilt attestation blob missing: %v", err)
	}
}

func TestBuildProducesSignedRepoAndIsIdempotent(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	root := filepath.Dir(mPath)

	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	res1, err := b.Build(BuildOptions{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !res1.Changed || res1.SerialAfter != 1 {
		t.Fatalf("first build: changed=%v serial=%d", res1.Changed, res1.SerialAfter)
	}
	out := filepath.Join(root, "public")
	artName := readIndex(t, out).Packages["hello"][0].Artifact
	for _, f := range []string{
		"index.json", "index.json.minisig",
		"trust.json", "trust.json.minisig",
		artName, artName + ".minisig",
		"trust_root.pub",
	} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Fatalf("missing published %s: %v", f, err)
		}
	}

	// Second build, no source change → no-op, serial unchanged.
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	res2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Changed || res2.SerialAfter != 1 {
		t.Fatalf("second build should be no-op: changed=%v serial=%d", res2.Changed, res2.SerialAfter)
	}
}

func TestBuildSerialDoesNotRegressWhenCacheLost(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	root := filepath.Dir(mPath)

	// Build, change the source, build again so the published serial reaches 2.
	b, _ := NewBuilder(mPath, keyDir, "pw")
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pkgs", "hello", "content", "bin", "hello"), []byte("#!/bin/sh\necho v2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	b2, _ := NewBuilder(mPath, keyDir, "pw")
	res2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res2.SerialAfter != 2 {
		t.Fatalf("setup: expected published serial 2, got %d", res2.SerialAfter)
	}

	// Simulate losing the build cache (disk loss, fresh CI runner, or the
	// corrupt-cache reset in LoadBuildCache). The serial must never drop below
	// the already-published value: a reused serial would let a mirror pin
	// consumers to a stale-but-validly-signed index.
	if err := os.Remove(filepath.Join(keyDir, "example.build-cache.json")); err != nil {
		t.Fatal(err)
	}
	b3, _ := NewBuilder(mPath, keyDir, "pw")
	res3, err := b3.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res3.SerialAfter < 2 {
		t.Fatalf("serial regressed after cache loss: got %d, want >= 2", res3.SerialAfter)
	}
}

// TestBuildRevisionFloorsAgainstPublishedIndexOnCacheLoss pins the revision
// analogue of the serial floor: losing the build cache while republishing the
// SAME version with NEW content must continue the published ordinal
// (published+1), not reset to 1.
func TestBuildRevisionFloorsAgainstPublishedIndexOnCacheLoss(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	root := filepath.Dir(mPath)
	pub := filepath.Join(root, "public")

	// Build (rev 1), mutate, build (rev 2).
	b1, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b1.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	mutatePkgSrc(t, filepath.Join(root, "pkgs", "hello"))
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b2.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	if rev := readIndex(t, pub).Packages["hello"][0].Revision; rev != 2 {
		t.Fatalf("setup: revision = %d, want 2", rev)
	}

	// Lose the cache, mutate again, rebuild: the published index says rev 2 for
	// this (name, version), the new content differs, so the ordinal must be 3.
	if err := os.Remove(filepath.Join(keyDir, "example.build-cache.json")); err != nil {
		t.Fatal(err)
	}
	mutatePkgSrc(t, filepath.Join(root, "pkgs", "hello"))
	b3, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b3.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	if rev := readIndex(t, pub).Packages["hello"][0].Revision; rev != 3 {
		t.Fatalf("revision after cache loss = %d, want 3 (published floor)", rev)
	}
}

// TestBuildRevisionKeptOnCacheLossWithUnchangedContent pins the same-hash arm
// of the published-index floor: a cache loss followed by a rebuild of
// byte-identical content must keep the published revision, not reset to 1.
func TestBuildRevisionKeptOnCacheLossWithUnchangedContent(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	root := filepath.Dir(mPath)
	pub := filepath.Join(root, "public")

	// Build (rev 1), mutate, build (rev 2).
	b1, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b1.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	mutatePkgSrc(t, filepath.Join(root, "pkgs", "hello"))
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b2.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	if rev := readIndex(t, pub).Packages["hello"][0].Revision; rev != 2 {
		t.Fatalf("setup: revision = %d, want 2", rev)
	}

	// Lose the cache but leave the source untouched: the rebuild produces the
	// SAME content hash the index already publishes, so the revision stays 2.
	if err := os.Remove(filepath.Join(keyDir, "example.build-cache.json")); err != nil {
		t.Fatal(err)
	}
	b3, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b3.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	if rev := readIndex(t, pub).Packages["hello"][0].Revision; rev != 2 {
		t.Fatalf("revision after cache loss with unchanged content = %d, want 2", rev)
	}
}

func TestBuildBumpsSerialOnChange(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	root := filepath.Dir(mPath)
	b, _ := NewBuilder(mPath, keyDir, "pw")
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	// Change the package source.
	if err := os.WriteFile(filepath.Join(root, "pkgs", "hello", "content", "bin", "hello"), []byte("#!/bin/sh\necho changed\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	b2, _ := NewBuilder(mPath, keyDir, "pw")
	res, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.SerialAfter != 2 {
		t.Fatalf("expected serial bump to 2: changed=%v serial=%d", res.Changed, res.SerialAfter)
	}
}

func TestPendingReflectsState(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	root := filepath.Dir(mPath)
	b, _ := NewBuilder(mPath, keyDir, "pw")
	pending, reason, err := b.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if !pending || reason == "" {
		t.Fatalf("never-built repo should be pending with a reason, got pending=%v reason=%q", pending, reason)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	b2, _ := NewBuilder(mPath, keyDir, "pw")
	pending, reason, err = b2.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if pending || reason != "" {
		t.Fatalf("freshly built repo should not be pending, got pending=%v reason=%q", pending, reason)
	}
	// Touch source → pending again.
	if err := os.WriteFile(filepath.Join(root, "pkgs", "hello", "content", "bin", "hello"), []byte("#!/bin/sh\necho x\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	b3, _ := NewBuilder(mPath, keyDir, "pw")
	pending, reason, err = b3.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if !pending || reason == "" {
		t.Fatalf("changed source should be pending with a reason, got pending=%v reason=%q", pending, reason)
	}
}

func TestBuildRejectsKeyInsideOutput(t *testing.T) {
	root := t.TempDir()
	insideKeyDir := filepath.Join(root, "public", "keys")
	if err := os.MkdirAll(insideKeyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	kp, _ := GenerateKeypair()
	keyPath := filepath.Join(insideKeyDir, "example.key")
	if err := SaveKey(keyPath, kp, "pw", KDFScrypt); err != nil {
		t.Fatal(err)
	}
	manifest := "schema: polypkg.repo/v1\nsource: example\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\npackages: {}\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := NewBuilder(mPath, insideKeyDir, "pw")
	if err == nil {
		_, err = b.Build(BuildOptions{})
	}
	if err == nil {
		t.Fatal("expected error: key/cache must not live inside output")
	}
}

func TestNewBuilderWrongPassword(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	if _, err := NewBuilder(mPath, keyDir, "WRONG"); err == nil {
		t.Fatal("expected error for wrong key password")
	}
}

func TestBuildRebuildsOnKeyRotation(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	root := filepath.Dir(mPath)
	out := filepath.Join(root, "public")

	// First build with original key.
	b1, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder (first): %v", err)
	}
	res1, err := b1.Build(BuildOptions{})
	if err != nil {
		t.Fatalf("Build (first): %v", err)
	}
	if !res1.Changed || res1.SerialAfter != 1 {
		t.Fatalf("first build: changed=%v serial=%d", res1.Changed, res1.SerialAfter)
	}
	firstPub, err := os.ReadFile(filepath.Join(out, "trust_root.pub"))
	if err != nil {
		t.Fatalf("read trust_root.pub after first build: %v", err)
	}

	// Rotate the key: generate a new keypair and overwrite the same key path.
	// The manifest's key.path is an absolute path stored in keyDir.
	manifestData, err := os.ReadFile(mPath)
	if err != nil {
		t.Fatal(err)
	}
	// Extract the key path from the manifest by parsing it.
	b1Again, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := resolveRel(filepath.Dir(mPath), b1Again.insp.layout.manifest.Key.Path)

	newKP, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if err := SaveKey(keyPath, newKP, "pw", KDFScrypt); err != nil {
		t.Fatalf("SaveKey (rotation): %v", err)
	}
	_ = manifestData // manifest unchanged; only key file on disk changed

	// Second build with new key — must detect key rotation.
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder (after rotation): %v", err)
	}
	res2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatalf("Build (after rotation): %v", err)
	}
	if !res2.Changed {
		t.Fatal("expected Changed=true after key rotation")
	}
	if res2.SerialAfter != 2 {
		t.Fatalf("expected serial 2 after rotation, got %d", res2.SerialAfter)
	}

	// trust_root.pub must now reflect the new key.
	newPub, err := os.ReadFile(filepath.Join(out, "trust_root.pub"))
	if err != nil {
		t.Fatalf("read trust_root.pub after rotation: %v", err)
	}
	if bytes.Equal(firstPub, newPub) {
		t.Fatal("trust_root.pub unchanged after key rotation")
	}
	wantPub := []byte(newKP.PublicKeyFile("polypkg " + b2.insp.layout.manifest.Source + " trust root"))
	if !bytes.Equal(newPub, wantPub) {
		t.Fatalf("trust_root.pub content mismatch after rotation\ngot:  %q\nwant: %q", newPub, wantPub)
	}
}

func TestBuildDropsRemovedPackageFromIndex(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()

	// Set up two package source directories: hello and world.
	helloDir := filepath.Join(root, "pkgs", "hello")
	worldDir := filepath.Join(root, "pkgs", "world")
	if err := os.MkdirAll(helloDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(worldDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writePkgSrc(t, helloDir) // name=hello version=1.0.0

	// Write a minimal world package source.
	worldManifest := "schema: polypkg.package/v1\nname: world\nversion: 1.0.0\nactions: []\n"
	if err := os.WriteFile(filepath.Join(worldDir, "polypkg.yaml"), []byte(worldManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(worldDir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worldDir, "content", "bin", "world"), []byte("#!/bin/sh\necho world\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "example.key")
	if err := SaveKey(keyPath, kp, "pw", KDFScrypt); err != nil {
		t.Fatal(err)
	}

	// Manifest with both packages.
	twoPackageManifest := "schema: polypkg.repo/v1\nsource: example\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    - source: ./pkgs/hello\n  world:\n    - source: ./pkgs/world\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(twoPackageManifest), 0o644); err != nil {
		t.Fatal(err)
	}

	b1, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder (two packages): %v", err)
	}
	res1, err := b1.Build(BuildOptions{})
	if err != nil {
		t.Fatalf("Build (two packages): %v", err)
	}
	if !res1.Changed || res1.SerialAfter != 1 {
		t.Fatalf("first build: changed=%v serial=%d", res1.Changed, res1.SerialAfter)
	}

	// Confirm both appear in the index.
	out := filepath.Join(root, "public")
	idxData, err := os.ReadFile(filepath.Join(out, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx1 struct {
		Packages map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(idxData, &idx1); err != nil {
		t.Fatalf("unmarshal index after first build: %v", err)
	}
	if _, ok := idx1.Packages["hello"]; !ok {
		t.Fatal("hello missing from first index")
	}
	if _, ok := idx1.Packages["world"]; !ok {
		t.Fatal("world missing from first index")
	}

	// Rewrite manifest with only hello.
	onePackageManifest := "schema: polypkg.repo/v1\nsource: example\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    - source: ./pkgs/hello\n"
	if err := os.WriteFile(mPath, []byte(onePackageManifest), 0o644); err != nil {
		t.Fatal(err)
	}

	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder (one package): %v", err)
	}
	res2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatalf("Build (one package): %v", err)
	}
	if !res2.Changed {
		t.Fatal("expected Changed=true after removing world from manifest")
	}
	if res2.SerialAfter != 2 {
		t.Fatalf("expected serial 2, got %d", res2.SerialAfter)
	}

	// world must be absent from the new index.
	idxData2, err := os.ReadFile(filepath.Join(out, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx2 struct {
		Packages map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(idxData2, &idx2); err != nil {
		t.Fatalf("unmarshal index after second build: %v", err)
	}
	if _, ok := idx2.Packages["world"]; ok {
		t.Fatal("world still present in index after removal from manifest")
	}
	if _, ok := idx2.Packages["hello"]; !ok {
		t.Fatal("hello missing from index after world removal")
	}
}

func TestBuildReusesCachedArtifactOnHit(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	root := filepath.Dir(mPath)
	out := filepath.Join(root, "public")

	b1, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	if _, err := b1.Build(BuildOptions{}); err != nil {
		t.Fatalf("Build (first): %v", err)
	}

	artPath := filepath.Join(out, readIndex(t, out).Packages["hello"][0].Artifact)
	firstBytes, err := os.ReadFile(artPath)
	if err != nil {
		t.Fatalf("read artifact after first build: %v", err)
	}

	// Second build with no source change.
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder (second): %v", err)
	}
	res2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatalf("Build (second): %v", err)
	}
	if res2.Changed {
		t.Fatal("expected Changed=false on cache hit")
	}

	secondBytes, err := os.ReadFile(artPath)
	if err != nil {
		t.Fatalf("read artifact after second build: %v", err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("artifact bytes changed on cache hit — artifact was unnecessarily repacked")
	}
}

// writePkgSrcWithDepends writes a package source whose manifest declares a
// depends relation on "libc" >= "1.0". Used to test that relations are
// preserved in the published index through both build and cache-hit paths.
func writePkgSrcWithDepends(t *testing.T, dir string) {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n" +
		"depends:\n  - name: libc\n    version: \">=1.0\"\n"
	if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "content", "bin", "hello"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// readIndexEntry reads index.json from outDir and returns the first IndexEntry
// for pkgName, failing the test if it cannot be found or parsed.
func readIndexEntry(t *testing.T, outDir, pkgName string) schema.IndexEntry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(outDir, "index.json"))
	if err != nil {
		t.Fatalf("read index.json: %v", err)
	}
	var idx schema.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatalf("unmarshal index: %v", err)
	}
	entries, ok := idx.Packages[pkgName]
	if !ok || len(entries) == 0 {
		t.Fatalf("package %q not found in index", pkgName)
	}
	return entries[0]
}

// TestBuildPublishesDependsRelations verifies that a package manifest's
// depends/provides/conflicts/obsoletes relations survive into the published
// index.json on both the initial build path and the cache-hit path.
func TestBuildPublishesDependsRelations(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()
	pkgDir := filepath.Join(root, "pkgs", "hello")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writePkgSrcWithDepends(t, pkgDir)

	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "example.key")
	if err := SaveKey(keyPath, kp, "pw", KDFScrypt); err != nil {
		t.Fatal(err)
	}
	manifest := "schema: polypkg.repo/v1\nsource: example\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    - source: ./pkgs/hello\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "public")

	// First build: relations must appear in the index (rebuild path).
	b1, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder (first): %v", err)
	}
	if _, err := b1.Build(BuildOptions{}); err != nil {
		t.Fatalf("Build (first): %v", err)
	}
	entry1 := readIndexEntry(t, out, "hello")
	if len(entry1.Depends) == 0 || entry1.Depends[0].Name != "libc" || entry1.Depends[0].Version != ">=1.0" {
		t.Fatalf("first build: expected depends=[{libc >=1.0}], got %v", entry1.Depends)
	}

	// Second build with no source change: cache hit must also carry relations.
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder (second): %v", err)
	}
	res2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatalf("Build (second): %v", err)
	}
	if res2.Changed {
		t.Fatal("expected no-op second build (cache hit)")
	}
	entry2 := readIndexEntry(t, out, "hello")
	if len(entry2.Depends) == 0 || entry2.Depends[0].Name != "libc" || entry2.Depends[0].Version != ">=1.0" {
		t.Fatalf("cache-hit build: expected depends=[{libc >=1.0}], got %v", entry2.Depends)
	}
}

// writePkgSrcWithWeakDeps writes a package source whose manifest declares
// recommends and suggests relations. Used to test that weak dependencies are
// preserved in the published index through both the rebuild and cache-hit paths.
func writePkgSrcWithWeakDeps(t *testing.T, dir string) {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n" +
		"recommends:\n  - name: foo-extras\n    version: \">=1.0\"\n" +
		"suggests:\n  - name: foo-docs\n"
	if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "content", "bin", "hello"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestBuildPublishesWeakDependencies verifies that a package manifest's
// recommends and suggests relations survive into the published index.json on
// both the initial build path (rebuild) and the cache-hit path (second build,
// no source change).
func TestBuildPublishesWeakDependencies(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()
	pkgDir := filepath.Join(root, "pkgs", "hello")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writePkgSrcWithWeakDeps(t, pkgDir)

	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "example.key")
	if err := SaveKey(keyPath, kp, "pw", KDFScrypt); err != nil {
		t.Fatal(err)
	}
	manifest := "schema: polypkg.repo/v1\nsource: example\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    - source: ./pkgs/hello\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "public")

	// First build: weak deps must appear in the index (rebuild path).
	b1, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder (first): %v", err)
	}
	if _, err := b1.Build(BuildOptions{}); err != nil {
		t.Fatalf("Build (first): %v", err)
	}
	entry1 := readIndexEntry(t, out, "hello")
	if len(entry1.Recommends) == 0 || entry1.Recommends[0].Name != "foo-extras" {
		t.Fatalf("first build: expected recommends=[{foo-extras}], got %v", entry1.Recommends)
	}
	if entry1.Recommends[0].Version != ">=1.0" {
		t.Fatalf("first build: expected recommends[0].Version=>=1.0, got %q", entry1.Recommends[0].Version)
	}
	if len(entry1.Suggests) == 0 || entry1.Suggests[0].Name != "foo-docs" {
		t.Fatalf("first build: expected suggests=[{foo-docs}], got %v", entry1.Suggests)
	}

	// Second build with no source change: cache-hit path must also carry weak deps.
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder (second): %v", err)
	}
	res2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatalf("Build (second): %v", err)
	}
	if res2.Changed {
		t.Fatal("expected no-op second build (cache hit)")
	}
	entry2 := readIndexEntry(t, out, "hello")
	if len(entry2.Recommends) == 0 || entry2.Recommends[0].Name != "foo-extras" {
		t.Fatalf("cache-hit build: expected recommends=[{foo-extras}], got %v", entry2.Recommends)
	}
	if entry2.Recommends[0].Version != ">=1.0" {
		t.Fatalf("cache-hit build: expected recommends[0].Version=>=1.0, got %q", entry2.Recommends[0].Version)
	}
	if len(entry2.Suggests) == 0 || entry2.Suggests[0].Name != "foo-docs" {
		t.Fatalf("cache-hit build: expected suggests=[{foo-docs}], got %v", entry2.Suggests)
	}
}

func TestWriteAtomicBatchAbortsBeforePublishingOnWriteFailure(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")

	// Pre-create b's temp path as a directory so writing it fails partway
	// through the batch (after a's temp is already written).
	if err := os.Mkdir(b+".tmp", 0o755); err != nil {
		t.Fatal(err)
	}

	err := writeAtomicBatch([]publishFile{
		{path: a, body: []byte("AAA")},
		{path: b, body: []byte("BBB")},
	})
	if err == nil {
		t.Fatal("expected error when a temp file cannot be written")
	}

	// Nothing may be published: staging failed before any rename, so 'a' must
	// not exist as a final file, and no .tmp may be left behind.
	if _, statErr := os.Stat(a); !os.IsNotExist(statErr) {
		t.Fatalf("a was published despite an aborted batch: %v", statErr)
	}
	if _, statErr := os.Stat(a + ".tmp"); !os.IsNotExist(statErr) {
		t.Fatal("a.tmp was left behind after an aborted batch")
	}
}

func TestWriteAtomicBatchCommitsAll(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")

	if err := writeAtomicBatch([]publishFile{
		{path: a, body: []byte("AAA")},
		{path: b, body: []byte("BBB")},
	}); err != nil {
		t.Fatalf("writeAtomicBatch: %v", err)
	}

	for name, want := range map[string]string{a: "AAA", b: "BBB"} {
		got, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
		if _, statErr := os.Stat(name + ".tmp"); !os.IsNotExist(statErr) {
			t.Fatalf("%s.tmp left behind after commit", name)
		}
	}
}

// writeDupVersionSources lays out two package source directories under
// root/pkgs/{a,b}, both named hello and both at version 1.0.0 — the shared
// fixture for the duplicate-version guard tests below, where one manifest
// entry per source declaring the same version is exactly what the guard
// rejects.
func writeDupVersionSources(t *testing.T, root string) {
	t.Helper()
	for _, sub := range []string{"a", "b"} {
		dir := filepath.Join(root, "pkgs", sub)
		if err := os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		manifest := "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"
		if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "content", "bin", "hello"),
			[]byte("#!/bin/sh\necho "+sub+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// writeDupVersionKey generates and saves a scrypt-encrypted signing key under
// keyDir for the duplicate-version guard tests, returning its path.
func writeDupVersionKey(t *testing.T, keyDir string) string {
	t.Helper()
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "repo.key")
	if err := SaveKey(keyPath, kp, "pw", KDFScrypt); err != nil {
		t.Fatal(err)
	}
	return keyPath
}

// assertDupVersionError fails t unless err mentions the duplicated version and
// both offending source paths, so a publisher can identify and fix the
// manifest from the error alone.
func assertDupVersionError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("Build accepted two entries declaring hello 1.0.0; want an error")
	}
	for _, want := range []string{"1.0.0", "./pkgs/a", "./pkgs/b"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q; the publisher needs both sources named", err, want)
		}
	}
}

// TestBuildRejectsDuplicateVersions covers two manifest entries under one name
// resolving to the same version. The index keys versions within a name, so one
// would silently overwrite the other and the repository would not match the
// manifest that produced it. Both entries are fresh packs, exercising the
// post-PackArtifact guard.
func TestBuildRejectsDuplicateVersions(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()

	writeDupVersionSources(t, root)
	keyPath := writeDupVersionKey(t, keyDir)

	mPath := filepath.Join(root, "polypkg-repo.yaml")
	body := "schema: polypkg.repo/v1\nsource: repo\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    - source: ./pkgs/a\n    - source: ./pkgs/b\n"
	if err := os.WriteFile(mPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Build(BuildOptions{SkipAttestations: true})
	assertDupVersionError(t, err)
}

// TestBuildRejectsDuplicateVersionsOnCacheHit covers the same duplicate as
// TestBuildRejectsDuplicateVersions, but forces source "a" through the build
// cache instead of a fresh pack: build once with only "a", then add "b"
// (same version) and rebuild. The source branch's cache-hit continue returns
// before PackArtifact runs, so the post-PackArtifact duplicate-version guard
// never executes for a cached entry — that path needs its own guard, added at
// the cache-hit continue itself. Without this test, that guard could regress
// unnoticed: nothing else in the suite reaches it.
func TestBuildRejectsDuplicateVersionsOnCacheHit(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()

	writeDupVersionSources(t, root)
	keyPath := writeDupVersionKey(t, keyDir)

	mPath := filepath.Join(root, "polypkg-repo.yaml")

	// First build: only source "a", so it lands in the build cache.
	body1 := "schema: polypkg.repo/v1\nsource: repo\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    - source: ./pkgs/a\n"
	if err := os.WriteFile(mPath, []byte(body1), 0o644); err != nil {
		t.Fatal(err)
	}
	b1, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b1.Build(BuildOptions{SkipAttestations: true}); err != nil {
		t.Fatalf("first build: %v", err)
	}

	// Second build: add source "b" declaring the same version. "a" is now a
	// cache hit; "b" is a fresh pack.
	body2 := "schema: polypkg.repo/v1\nsource: repo\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    - source: ./pkgs/a\n    - source: ./pkgs/b\n"
	if err := os.WriteFile(mPath, []byte(body2), 0o644); err != nil {
		t.Fatal(err)
	}
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	_, err = b2.Build(BuildOptions{SkipAttestations: true})
	assertDupVersionError(t, err)
}
