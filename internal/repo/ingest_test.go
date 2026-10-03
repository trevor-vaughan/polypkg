package repo

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// stagePrebuilt builds a real artifact from a throwaway source tree, then stages
// it (+ a carried, correctly-bound SLSA attestation) as a prebuilt input. Returns
// the manifest path and keyDir for a repo whose single package "hello" is a
// prebuilt entry. bind=false stages an attestation that binds nothing.
func stagePrebuilt(t *testing.T, bind bool) (mPath, keyDir string) {
	t.Helper()
	root := t.TempDir()
	keyDir = t.TempDir()

	srcDir := filepath.Join(root, "origin", "hello")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writePkgSrc(t, srcDir) // polypkg.yaml + content/bin/hello
	artifact, _, err := PackArtifact(srcDir)
	if err != nil {
		t.Fatalf("pack origin artifact: %v", err)
	}

	staging := filepath.Join(root, "staging")
	attDir := filepath.Join(staging, "hello-atts")
	if err := os.MkdirAll(attDir, 0o755); err != nil {
		t.Fatal(err)
	}
	artPath := filepath.Join(staging, "hello.tar.zst")
	if err := os.WriteFile(artPath, artifact, 0o644); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(srcDir, "content", "bin", "hello"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Bare(body)
	if !bind {
		digest = sha256Bare([]byte("mismatch"))
	}
	if err := os.WriteFile(filepath.Join(attDir, "slsa.json"), dsseSLSA(t, "bin/hello", digest), 0o644); err != nil {
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
	manifest := "schema: polypkg.repo/v1\nsource: example\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    - prebuilt:\n" +
		"        artifact: " + artPath + "\n" +
		"        attestations: " + attDir + "\n"
	mPath = filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return mPath, keyDir
}

func TestBuildIngestsPrebuiltArtifact(t *testing.T) {
	mPath, keyDir := stagePrebuilt(t, true)
	pub := filepath.Join(filepath.Dir(mPath), "public")
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatalf("build prebuilt: %v", err)
	}
	e := readIndex(t, pub).Packages["hello"][0]

	poolArt, err := os.ReadFile(filepath.Join(pub, e.Artifact))
	if err != nil {
		t.Fatalf("read pool artifact: %v", err)
	}
	staged, err := os.ReadFile(filepath.Join(filepath.Dir(mPath), "staging", "hello.tar.zst"))
	if err != nil {
		t.Fatal(err)
	}
	if string(poolArt) != string(staged) {
		t.Fatal("ingested pool artifact is not byte-identical to the staged fetch")
	}

	var carried, link, native int
	for _, r := range e.Attestations {
		switch {
		case r.Kind == schema.KindCarriedOpaque:
			carried++
			if r.SubjectScope != "content:bin/hello" {
				t.Fatalf("carried subject_scope = %q, want content:bin/hello", r.SubjectScope)
			}
		case r.Format == schema.FormatPolypkgLink:
			link++
		case r.Format == schema.FormatPolypkgSARIF:
			native++
		}
		if _, statErr := os.Stat(filepath.Join(pub, r.Artifact)); statErr != nil {
			t.Fatalf("attestation blob %s missing: %v", r.Artifact, statErr)
		}
	}
	if carried != 1 || link != 1 || native != 0 {
		t.Fatalf("carried=%d link=%d native=%d, want 1/1/0", carried, link, native)
	}
}

func TestBuildRefusesPrebuiltWithUnboundAttestation(t *testing.T) {
	mPath, keyDir := stagePrebuilt(t, false)
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err == nil {
		t.Fatal("expected refusal: prebuilt carried attestation binds nothing in the fetched bytes")
	}
}

func TestBuildRejectsPrebuiltNameMismatch(t *testing.T) {
	mPath, keyDir := stagePrebuilt(t, true)
	// Rewrite the manifest key from "hello" to "goodbye" — the inner polypkg.yaml
	// still says name: hello, so ingest must refuse the mismatch.
	raw, err := os.ReadFile(mPath)
	if err != nil {
		t.Fatal(err)
	}
	swapped := strings.Replace(string(raw), "\n  hello:\n", "\n  goodbye:\n", 1)
	if swapped == string(raw) {
		t.Fatal("manifest rewrite did not change the package key")
	}
	if err := os.WriteFile(mPath, []byte(swapped), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err == nil {
		t.Fatal("expected refusal: manifest key does not match the fetched package name")
	}
}

func TestBuildPrebuiltIsIdempotent(t *testing.T) {
	mPath, keyDir := stagePrebuilt(t, true)
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	r1, err := b.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r2.Changed {
		t.Fatalf("second prebuilt build reported Changed=true (serial %d→%d), want a no-op", r2.SerialBefore, r2.SerialAfter)
	}
	if r2.SerialAfter != r1.SerialAfter {
		t.Fatalf("serial moved on a no-op prebuilt rebuild: %d → %d", r1.SerialAfter, r2.SerialAfter)
	}
}

// writePkgSrcNamed writes a package source named `name` with content/bin/<name>.
func writePkgSrcNamed(t *testing.T, dir, name string) {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: " + name + "\nversion: 1.0.0\nactions: []\n"
	if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "content", "bin", name), []byte("#!/bin/sh\necho "+name+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

type stagedPkg struct {
	name       string
	artPath    string
	attDir     string
	bundlePath string // "" if none
	nativePath string // "" if none
}

// stageOnePrebuilt builds an artifact named `name`, stages it + a bound SLSA
// attestation under root/staging/<name>, and (if bundle != nil) stages a
// trust-bundle.json with those bytes.
func stageOnePrebuilt(t *testing.T, root, name string, bundle []byte) stagedPkg {
	t.Helper()
	srcDir := filepath.Join(root, "origin", name)
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writePkgSrcNamed(t, srcDir, name)
	artifact, _, err := PackArtifact(srcDir)
	if err != nil {
		t.Fatalf("pack %s: %v", name, err)
	}
	stg := filepath.Join(root, "staging", name)
	attDir := filepath.Join(stg, "atts")
	if err := os.MkdirAll(attDir, 0o755); err != nil {
		t.Fatal(err)
	}
	artPath := filepath.Join(stg, name+".tar.zst")
	if err := os.WriteFile(artPath, artifact, 0o644); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(srcDir, "content", "bin", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attDir, "slsa.json"), dsseSLSA(t, "bin/"+name, sha256Bare(body)), 0o644); err != nil {
		t.Fatal(err)
	}
	sp := stagedPkg{name: name, artPath: artPath, attDir: attDir}
	if bundle != nil {
		bp := filepath.Join(stg, "trust-bundle.json")
		if err := os.WriteFile(bp, bundle, 0o644); err != nil {
			t.Fatal(err)
		}
		sp.bundlePath = bp
	}
	return sp
}

// writePrebuiltManifest writes a repo manifest with the given staged prebuilt
// packages and a fresh key; returns (manifestPath, keyDir).
func writePrebuiltManifest(t *testing.T, root string, pkgs ...stagedPkg) (mPath, keyDir string) {
	t.Helper()
	keyDir = t.TempDir()
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "example.key")
	if err := SaveKey(keyPath, kp, "pw", KDFScrypt); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	sb.WriteString("schema: polypkg.repo/v1\nsource: example\noutput: ./public\n")
	sb.WriteString("key:\n  path: " + keyPath + "\n  kdf: scrypt\n")
	sb.WriteString("packages:\n")
	for _, p := range pkgs {
		sb.WriteString("  " + p.name + ":\n    - prebuilt:\n")
		sb.WriteString("        artifact: " + p.artPath + "\n")
		sb.WriteString("        attestations: " + p.attDir + "\n")
		if p.bundlePath != "" {
			sb.WriteString("        trust_bundle: " + p.bundlePath + "\n")
		}
		if p.nativePath != "" {
			sb.WriteString("        native_attestation: " + p.nativePath + "\n")
		}
	}
	mPath = filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return mPath, keyDir
}

// bundleWithKey renders a valid polypkg.trust-bundle/v1 with one builder key.
func bundleWithKey(t *testing.T, keyID, pubB64 string) []byte {
	t.Helper()
	tb := schema.TrustBundle{
		Schema:  "polypkg.trust-bundle/v1",
		Source:  "upstream",
		Serial:  7,
		Expires: "2099-01-01T00:00:00Z",
		BuilderKeys: []schema.BuilderKey{{
			KeyID: keyID, PublicKey: pubB64, Algo: "ed25519", ValidFrom: "2020-01-01T00:00:00Z",
		}},
	}
	raw, err := json.Marshal(&tb)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBuildCarriesTrustBundleForward(t *testing.T) {
	root := t.TempDir()
	sp := stageOnePrebuilt(t, root, "hello", bundleWithKey(t, "aa11bb22cc33dd44", "QUJDRA=="))
	mPath, keyDir := writePrebuiltManifest(t, root, sp)
	pub := filepath.Join(root, "public")
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatalf("build with carry-forward: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(pub, "trust-bundle.json"))
	if err != nil {
		t.Fatalf("repo did not emit trust-bundle.json: %v", err)
	}
	got, err := schema.ParseTrustBundle(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("emitted trust-bundle.json is invalid: %v", err)
	}
	if len(got.BuilderKeys) != 1 || got.BuilderKeys[0].KeyID != "aa11bb22cc33dd44" {
		t.Fatalf("carried builder keys = %+v", got.BuilderKeys)
	}
	if got.Source != "example" {
		t.Fatalf("carried bundle source = %q, want local source example", got.Source)
	}
	if _, statErr := os.Stat(filepath.Join(pub, "trust-bundle.json.minisig")); statErr != nil {
		t.Fatalf("trust-bundle.json.minisig missing: %v", statErr)
	}
}

func TestBuildEmitsNoTrustBundleWhenNoneStaged(t *testing.T) {
	root := t.TempDir()
	sp := stageOnePrebuilt(t, root, "hello", nil) // no bundle
	mPath, keyDir := writePrebuiltManifest(t, root, sp)
	pub := filepath.Join(root, "public")
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(filepath.Join(pub, "trust-bundle.json")); statErr == nil {
		t.Fatal("emitted trust-bundle.json with no staged bundle (backward-compat break)")
	}
}

func TestBuildMergesCarriedBundles(t *testing.T) {
	root := t.TempDir()
	h := stageOnePrebuilt(t, root, "hello", bundleWithKey(t, "1111111111111111", "QUFB"))
	w := stageOnePrebuilt(t, root, "world", bundleWithKey(t, "2222222222222222", "QkJC"))
	mPath, keyDir := writePrebuiltManifest(t, root, h, w)
	pub := filepath.Join(root, "public")
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatalf("build merge: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(pub, "trust-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := schema.ParseTrustBundle(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, k := range got.BuilderKeys {
		ids[k.KeyID] = true
	}
	if len(got.BuilderKeys) != 2 || !ids["1111111111111111"] || !ids["2222222222222222"] {
		t.Fatalf("merged builder keys = %+v, want both 1111… and 2222…", got.BuilderKeys)
	}
}

func TestBuildRejectsConflictingCarriedBundleKeyID(t *testing.T) {
	root := t.TempDir()
	// Same key_id "dup", DIFFERENT public_key → fail-closed.
	h := stageOnePrebuilt(t, root, "hello", bundleWithKey(t, "dddddddddddddddd", "QUFB"))
	w := stageOnePrebuilt(t, root, "world", bundleWithKey(t, "dddddddddddddddd", "QkJC"))
	mPath, keyDir := writePrebuiltManifest(t, root, h, w)
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err == nil {
		t.Fatal("expected refusal: two carried bundles vouch for the same key_id with different material")
	}
}

func TestBuildCarryForwardIsIdempotent(t *testing.T) {
	root := t.TempDir()
	sp := stageOnePrebuilt(t, root, "hello", bundleWithKey(t, "aa11bb22cc33dd44", "QUJDRA=="))
	mPath, keyDir := writePrebuiltManifest(t, root, sp)
	pub := filepath.Join(root, "public")
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	r1, err := b.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(pub, "trust-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r2.Changed {
		t.Fatalf("second carry-forward build reported Changed=true (serial %d→%d), want no-op", r2.SerialBefore, r2.SerialAfter)
	}
	if r2.SerialAfter != r1.SerialAfter {
		t.Fatalf("serial moved on a no-op carry-forward rebuild: %d → %d", r1.SerialAfter, r2.SerialAfter)
	}
	after, err := os.ReadFile(filepath.Join(pub, "trust-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("trust-bundle.json bytes changed on a no-op rebuild")
	}
}

func TestBuildCarryForwardDetectsKeyMaterialChange(t *testing.T) {
	root := t.TempDir()
	sp := stageOnePrebuilt(t, root, "hello", bundleWithKey(t, "aa11bb22cc33dd44", "QUJDRA=="))
	mPath, keyDir := writePrebuiltManifest(t, root, sp)
	pub := filepath.Join(root, "public")
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	r1, err := b.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Upstream reuses the SAME key_id with DIFFERENT material (a rotation-policy
	// violation). The republish must NOT silently keep serving the stale key: it
	// must bump the serial and publish the new material.
	if err := os.WriteFile(sp.bundlePath, bundleWithKey(t, "aa11bb22cc33dd44", "Q0RFRg=="), 0o644); err != nil {
		t.Fatal(err)
	}
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Changed || r2.SerialAfter == r1.SerialAfter {
		t.Fatalf("changed key material did not bump serial: r1=%d r2.Changed=%v r2=%d", r1.SerialAfter, r2.Changed, r2.SerialAfter)
	}
	raw, err := os.ReadFile(filepath.Join(pub, "trust-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := schema.ParseTrustBundle(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.BuilderKeys) != 1 || got.BuilderKeys[0].PublicKey != "Q0RFRg==" {
		t.Fatalf("published key material not updated: %+v", got.BuilderKeys)
	}
}

// bundleWithRoots renders a valid trust-bundle/v1 with one builder key and the
// given sigstore roots.
func bundleWithRoots(t *testing.T, keyID, pubB64 string, roots ...schema.SigstoreRoot) []byte {
	t.Helper()
	tb := schema.TrustBundle{
		Schema:  "polypkg.trust-bundle/v1",
		Source:  "upstream",
		Serial:  7,
		Expires: "2099-01-01T00:00:00Z",
		BuilderKeys: []schema.BuilderKey{{
			KeyID: keyID, PublicKey: pubB64, Algo: "ed25519", ValidFrom: "2020-01-01T00:00:00Z",
		}},
		SigstoreRoots: roots,
	}
	raw, err := json.Marshal(&tb)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBuildMergesSigstoreRootsDeduped(t *testing.T) {
	root := t.TempDir()
	shared := schema.SigstoreRoot{ValidFrom: "2020-01-01T00:00:00Z", FulcioCA: []string{"Q0Ex"}, RekorKeys: []string{"UjE="}}
	distinct := schema.SigstoreRoot{ValidFrom: "2021-01-01T00:00:00Z", FulcioCA: []string{"Q0Ey"}, RekorKeys: []string{"UjI="}}
	h := stageOnePrebuilt(t, root, "hello", bundleWithRoots(t, "1111111111111111", "QUFB", shared))
	w := stageOnePrebuilt(t, root, "world", bundleWithRoots(t, "2222222222222222", "QkJC", shared, distinct))
	mPath, keyDir := writePrebuiltManifest(t, root, h, w)
	pub := filepath.Join(root, "public")
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatalf("build merge roots: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(pub, "trust-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := schema.ParseTrustBundle(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SigstoreRoots) != 2 {
		t.Fatalf("merged sigstore roots = %d, want 2 (shared deduped + distinct)", len(got.SigstoreRoots))
	}
	froms := map[string]bool{}
	for i := range got.SigstoreRoots {
		froms[got.SigstoreRoots[i].ValidFrom] = true
	}
	if !froms["2020-01-01T00:00:00Z"] || !froms["2021-01-01T00:00:00Z"] {
		t.Fatalf("merged roots missing expected ValidFrom values: %+v", got.SigstoreRoots)
	}
}

func TestPendingReflectsPrebuiltState(t *testing.T) {
	root := t.TempDir()
	sp := stageOnePrebuilt(t, root, "hello", nil)
	mPath, keyDir := writePrebuiltManifest(t, root, sp)

	// Never built → pending.
	insp, err := NewInspector(mPath, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if pending, _, perr := insp.Pending(); perr != nil || !pending {
		t.Fatalf("never-built prebuilt repo: pending=%v err=%v, want pending", pending, perr)
	}

	// Build, then a FRESH inspector must report NOT pending (this is the regression).
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	insp2, err := NewInspector(mPath, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	pending, reason, err := insp2.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if pending {
		t.Fatalf("freshly-built prebuilt repo reported pending (reason=%q); status is broken for prebuilt", reason)
	}

	// Change the staged artifact bytes → pending again.
	srcDir := filepath.Join(root, "origin", "hello")
	if err := os.WriteFile(filepath.Join(srcDir, "content", "bin", "hello"), []byte("#!/bin/sh\necho changed\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	artifact, _, err := PackArtifact(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sp.artPath, artifact, 0o644); err != nil {
		t.Fatal(err)
	}
	insp3, err := NewInspector(mPath, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if pending, _, perr := insp3.Pending(); perr != nil || !pending {
		t.Fatalf("changed prebuilt artifact: pending=%v err=%v, want pending", pending, perr)
	}
}

// A build that carries a trust bundle, then a later build into the SAME output
// dir that carries none, must prune the now-orphaned trust-bundle.json + .minisig
// (which would otherwise keep vouching for dropped upstream builder keys), re-sign
// the trust set, and bump the serial. A third no-op build stays stable.
func TestBuildPrunesOrphanedTrustBundleWhenCarryDropped(t *testing.T) {
	root := t.TempDir()
	pub := filepath.Join(root, "public")

	// Build 1: prebuilt carries a trust bundle -> trust-bundle.json published.
	sp := stageOnePrebuilt(t, root, "hello", bundleWithKey(t, "aa11bb22cc33dd44", "QUJDRA=="))
	mPath, keyDir := writePrebuiltManifest(t, root, sp)
	b1, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	r1, err := b1.Build(BuildOptions{})
	if err != nil {
		t.Fatalf("build 1 (carry): %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(pub, "trust-bundle.json")); statErr != nil {
		t.Fatalf("build 1 did not publish trust-bundle.json: %v", statErr)
	}

	// Drop the carried trust_bundle from the manifest, REUSING the same key and
	// output dir. The staged artifact + SLSA attestation are unchanged, so the
	// only difference between runs is the vanished bundle: without the fix this
	// second build is a no-op (Changed=false) and the orphan survives.
	manRaw, err := os.ReadFile(mPath)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, line := range strings.Split(string(manRaw), "\n") {
		if strings.Contains(line, "trust_bundle:") {
			continue
		}
		kept = append(kept, line)
	}
	if err := os.WriteFile(mPath, []byte(strings.Join(kept, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}

	// Build 2: carries no bundle -> prune + re-sign + serial bump.
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatalf("build 2 (drop carry): %v", err)
	}
	if !r2.Changed {
		t.Fatal("build 2 reported Changed=false; the orphaned trust bundle was not detected as a change")
	}
	if r2.SerialAfter != r1.SerialAfter+1 {
		t.Fatalf("serial did not bump on carry-drop: %d -> %d", r1.SerialAfter, r2.SerialAfter)
	}
	if _, statErr := os.Stat(filepath.Join(pub, "trust-bundle.json")); statErr == nil {
		t.Fatal("orphaned trust-bundle.json was not pruned")
	}
	if _, statErr := os.Stat(filepath.Join(pub, "trust-bundle.json.minisig")); statErr == nil {
		t.Fatal("orphaned trust-bundle.json.minisig was not pruned")
	}
	if _, statErr := os.Stat(filepath.Join(pub, "trust.json")); statErr != nil {
		t.Fatalf("trust.json missing after prune: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(pub, "index.json.minisig")); statErr != nil {
		t.Fatalf("index.json.minisig missing after prune: %v", statErr)
	}

	// Build 3: identical inputs, bundle already gone -> stable, no perpetual bump.
	b3, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	r3, err := b3.Build(BuildOptions{})
	if err != nil {
		t.Fatalf("build 3 (no-op): %v", err)
	}
	if r3.Changed {
		t.Fatal("build 3 reported Changed=true; prune is not idempotent (serial would climb forever)")
	}
	if r3.SerialAfter != r2.SerialAfter {
		t.Fatalf("serial moved on a no-op rebuild after prune: %d -> %d", r2.SerialAfter, r3.SerialAfter)
	}
}
