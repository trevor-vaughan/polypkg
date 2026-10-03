package mirror

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// bytesReader wraps a byte slice as an io.Reader for the schema parsers.
func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// buildLocalRepo builds a minimal signed repo (package "hello") and returns
// (repoOutputDir, trustRootPath) — a real, signed, file://-servable repository.
func buildLocalRepo(t *testing.T) (outDir, trustRoot string) {
	t.Helper()
	root := t.TempDir()
	keyDir := t.TempDir()
	pkgDir := filepath.Join(root, "pkgs", "hello")
	if err := os.MkdirAll(filepath.Join(pkgDir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "polypkg.yaml"),
		[]byte("schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "content", "bin", "hello"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	kp, err := repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "example.key")
	if err := repo.SaveKey(keyPath, kp, "pw", repo.KDFScrypt); err != nil {
		t.Fatal(err)
	}
	manifest := "schema: polypkg.repo/v1\nsource: upstream\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    source: ./pkgs/hello\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(repo.BuildOptions{}); err != nil {
		t.Fatalf("build fixture repo: %v", err)
	}
	outDir = filepath.Join(root, "public")
	trustRoot = filepath.Join(outDir, "trust_root.pub")
	return outDir, trustRoot
}

func TestPullVerifiesTrustAndIndex(t *testing.T) {
	outDir, trustRoot := buildLocalRepo(t)
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage,
	})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "hello" || res.Packages[0].Version != "1.0.0" {
		t.Fatalf("pulled = %+v, want one hello@1.0.0", res.Packages)
	}
	if res.Packages[0].ContentHash == "" {
		t.Fatal("pulled package missing content hash from the verified index")
	}
}

func TestPullRefusesWrongTrustRoot(t *testing.T) {
	outDir, _ := buildLocalRepo(t)
	_, otherRoot := buildLocalRepo(t) // a different repo's trust root
	stage := t.TempDir()
	if _, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: otherRoot, SourceName: "upstream", StageDir: stage,
	}); err == nil {
		t.Fatal("expected refusal: index signed by a different key than the pinned trust root")
	}
}

// dsseSLSAInline replicates internal/repo's test-only dsseSLSA helper (not
// importable across packages): a DSSE envelope wrapping an in-toto SLSA
// statement whose single subject's sha256 digest is the bare hex given. Binding
// at repo.Build time selects the content file by that digest.
func dsseSLSAInline(subjectName, sha256hex string) []byte {
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"name": subjectName, "digest": map[string]string{"sha256": sha256hex}}},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate":     map[string]any{},
	}
	stB, _ := json.Marshal(st)
	env := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(stB),
		"signatures":  []map[string]string{{"keyid": "k", "sig": "AA=="}},
	}
	b, _ := json.Marshal(env)
	return b
}

// buildLocalRepoWithCarried is buildLocalRepo plus a carried SLSA attestation
// bound to content/bin/hello, so the built upstream repo's index carries a
// carried-opaque attestation blob (+ a polypkg link attestation). It returns the
// repo keypair so callers can sign additional documents (e.g. a revocation list)
// that verify under the same trust root.
func buildLocalRepoWithCarried(t *testing.T) (outDir, trustRoot string, kp *repo.Keypair) {
	t.Helper()
	root := t.TempDir()
	keyDir := t.TempDir()
	pkgDir := filepath.Join(root, "pkgs", "hello")
	if err := os.MkdirAll(filepath.Join(pkgDir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "polypkg.yaml"),
		[]byte("schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	contentBytes := []byte("#!/bin/sh\necho hi\n")
	if err := os.WriteFile(filepath.Join(pkgDir, "content", "bin", "hello"), contentBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	// Carry a bound SLSA attestation: subject digest sha256 = the content file's
	// bytes, so repo.Build binds it to content:bin/hello (not "binds nothing").
	sum := sha256.Sum256(contentBytes)
	attDir := filepath.Join(pkgDir, "attestations")
	if err := os.MkdirAll(attDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attDir, "slsa.json"),
		dsseSLSAInline("bin/hello", hex.EncodeToString(sum[:])), 0o644); err != nil {
		t.Fatal(err)
	}
	var err error
	kp, err = repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "example.key")
	if err := repo.SaveKey(keyPath, kp, "pw", repo.KDFScrypt); err != nil {
		t.Fatal(err)
	}
	manifest := "schema: polypkg.repo/v1\nsource: upstream\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    source: ./pkgs/hello\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(repo.BuildOptions{}); err != nil {
		t.Fatalf("build carried fixture repo: %v", err)
	}
	outDir = filepath.Join(root, "public")
	trustRoot = filepath.Join(outDir, "trust_root.pub")
	return outDir, trustRoot, kp
}

// corruptOnePoolArtifact flips a byte in the first pool .tar.zst under outDir,
// so its bytes no longer match the signed hash.
func corruptOnePoolArtifact(t *testing.T, outDir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(outDir, "pool", "*.tar.zst"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no pool artifact found: %v", err)
	}
	b, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("empty pool artifact")
	}
	b[0] ^= 0xff
	if err := os.WriteFile(matches[0], b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPullStagesArtifactAndAttestations(t *testing.T) {
	outDir, trustRoot, _ := buildLocalRepoWithCarried(t)
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	p := res.Packages[0]
	got, err := os.ReadFile(p.ArtifactPath)
	if err != nil {
		t.Fatalf("staged artifact: %v", err)
	}
	if contentHash(got) != p.ContentHash {
		t.Fatalf("staged artifact hash %s != index content hash %s", contentHash(got), p.ContentHash)
	}
	ents, err := os.ReadDir(p.AttDir)
	if err != nil || len(ents) == 0 {
		t.Fatalf("no attestation blobs staged: err=%v n=%d", err, len(ents))
	}
	// Every staged attestation blob must be a *.att.json.
	for _, e := range ents {
		if filepath.Ext(e.Name()) != ".json" {
			t.Fatalf("unexpected staged file %q", e.Name())
		}
	}
}

func TestPullRefusesTamperedArtifact(t *testing.T) {
	outDir, trustRoot := buildLocalRepo(t)
	corruptOnePoolArtifact(t, outDir)
	stage := t.TempDir()
	if _, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage}); err == nil {
		t.Fatal("expected refusal: tampered upstream artifact bytes")
	}
}

func TestPullRefusesTamperedAttestation(t *testing.T) {
	outDir, trustRoot, _ := buildLocalRepoWithCarried(t)
	// Corrupt an attestation .att.json pool blob (not the artifact).
	matches, _ := filepath.Glob(filepath.Join(outDir, "pool", "*.att.json"))
	if len(matches) == 0 {
		t.Fatal("no attestation blob to corrupt")
	}
	b, _ := os.ReadFile(matches[0])
	b = append(b, ' ') // change bytes → hash+sig no longer match
	if err := os.WriteFile(matches[0], b, 0o644); err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	if _, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage}); err == nil {
		t.Fatal("expected refusal: tampered upstream attestation blob")
	}
}

func TestStagedPkgDirRejectsTraversal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "staging")
	bad := []struct{ name, version string }{
		{"../../evil", "1.0.0"}, {"ok", "../.."}, {"a/b", "1.0.0"},
		{"..", "1.0.0"}, {"", "1.0.0"}, {"ok", ""}, {"a\\b", "1.0.0"},
	}
	for _, tc := range bad {
		if _, err := stagedPkgDir(root, tc.name, tc.version); err == nil {
			t.Fatalf("expected rejection for name=%q version=%q", tc.name, tc.version)
		}
	}
	dir, err := stagedPkgDir(root, "hello", "1.0.0")
	if err != nil || dir != filepath.Join(root, "hello", "1.0.0") {
		t.Fatalf("normal pkg: dir=%q err=%v", dir, err)
	}
}

func TestStagedPkgDirRejectsUnsafeName(t *testing.T) {
	root := t.TempDir()
	for _, bad := range []string{"hello\noutput: /tmp/x", "a:b", "foo bar", "eviL!", "na/me"} {
		if _, err := stagedPkgDir(root, bad, "1.0.0"); err == nil {
			t.Errorf("stagedPkgDir accepted unsafe name %q", bad)
		}
	}
	// A legitimate name still works.
	if _, err := stagedPkgDir(root, "hello_world-1", "1.0.0"); err != nil {
		t.Errorf("stagedPkgDir rejected a valid name: %v", err)
	}
	// An unsafe version is rejected.
	if _, err := stagedPkgDir(root, "hello", "1.0.0\nx: y"); err == nil {
		t.Error("stagedPkgDir accepted unsafe version")
	}
}

func TestResolvePullSelectionLatestPerName(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"foo": {{Version: "1.0.0", ContentHash: "blake3:a"}, {Version: "2.0.0", ContentHash: "blake3:b"}},
	}}
	// bare name → latest (2.0.0)
	got, err := resolvePullSelection(idx, []string{"foo"})
	if err != nil || len(got) != 1 || got[0].version != "2.0.0" {
		t.Fatalf("bare name: got %+v err %v, want foo@2.0.0", got, err)
	}
	// name@version → exact
	got, err = resolvePullSelection(idx, []string{"foo@1.0.0"})
	if err != nil || len(got) != 1 || got[0].version != "1.0.0" {
		t.Fatalf("pinned: got %+v err %v, want foo@1.0.0", got, err)
	}
	// missing version → error
	if _, err := resolvePullSelection(idx, []string{"foo@9.9.9"}); err == nil {
		t.Fatal("expected error for missing version")
	}
	// duplicate name → error
	if _, err := resolvePullSelection(idx, []string{"foo", "foo@1.0.0"}); err == nil {
		t.Fatal("expected error for duplicate-name selection")
	}
}

// buildLocalRepoWithBundle builds a signed repo AND publishes a signed
// trust-bundle.json under outDir (signed by the repo's own key, so it verifies
// under the trust_root anchor). It returns the repo keypair so callers can sign
// additional documents (e.g. a revocation list) that verify under the same trust
// root.
func buildLocalRepoWithBundle(t *testing.T) (outDir, trustRoot string, kp *repo.Keypair) {
	t.Helper()
	root := t.TempDir()
	keyDir := t.TempDir()
	pkgDir := filepath.Join(root, "pkgs", "hello")
	if err := os.MkdirAll(filepath.Join(pkgDir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "polypkg.yaml"),
		[]byte("schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "content", "bin", "hello"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var err error
	kp, err = repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "example.key")
	if err := repo.SaveKey(keyPath, kp, "pw", repo.KDFScrypt); err != nil {
		t.Fatal(err)
	}
	manifest := "schema: polypkg.repo/v1\nsource: upstream\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    source: ./pkgs/hello\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(repo.BuildOptions{}); err != nil {
		t.Fatalf("build fixture repo: %v", err)
	}
	outDir = filepath.Join(root, "public")
	trustRoot = filepath.Join(outDir, "trust_root.pub")

	tb := schema.TrustBundle{
		Schema:  "polypkg.trust-bundle/v1",
		Source:  "upstream",
		Serial:  1,
		Expires: "2099-01-01T00:00:00Z",
		BuilderKeys: []schema.BuilderKey{{
			KeyID: "aa11bb22cc33dd44", PublicKey: "QUJDRA==", Algo: "ed25519", ValidFrom: "2020-01-01T00:00:00Z",
		}},
	}
	raw, err := json.Marshal(&tb)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "trust-bundle.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	sig := kp.SignTrustBundle(1, raw)
	if err := os.WriteFile(filepath.Join(outDir, "trust-bundle.json.minisig"), []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
	return outDir, trustRoot, kp
}

// publishRevocationList writes a repo-key-signed revocations.json (+ .minisig)
// under outDir so a native backend serving that root exposes it. The signature is
// made with the repo keypair, so it verifies under the published trust_root anchor.
func publishRevocationList(t *testing.T, outDir string, kp *repo.Keypair, rl schema.RevocationList) {
	t.Helper()
	raw, err := json.Marshal(&rl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "revocations.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	sig := kp.SignRevocationList(rl.Serial, raw)
	if err := os.WriteFile(filepath.Join(outDir, "revocations.json.minisig"), []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
}

// carriedOpaqueHash reads the built index and returns the content_hash of the
// first carried-opaque attestation ref (the external envelope carried through the
// build) — the hash a revocation list would target to strip that provenance.
func carriedOpaqueHash(t *testing.T, outDir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(outDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	idx, err := schema.ParseIndex(bytesReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, entries := range idx.Packages {
		for i := range entries {
			for j := range entries[i].Attestations {
				if entries[i].Attestations[j].Kind == schema.KindCarriedOpaque {
					return entries[i].Attestations[j].ContentHash
				}
			}
		}
	}
	t.Fatal("no carried-opaque attestation in the built index")
	return ""
}

func TestPullRefusesRevokedAttestation(t *testing.T) {
	outDir, trustRoot, kp := buildLocalRepoWithCarried(t)
	revoked := carriedOpaqueHash(t, outDir)
	publishRevocationList(t, outDir, kp, schema.RevocationList{
		Schema:              "polypkg.revocation-list/v1",
		Source:              "upstream",
		Serial:              1,
		Expires:             "2099-01-01T00:00:00Z",
		RevokedAttestations: []string{revoked},
	})
	stage := t.TempDir()
	_, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage})
	if err == nil {
		t.Fatal("expected refusal: pull must not launder an upstream-revoked attestation")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("error should name the revocation, got: %v", err)
	}
}

func TestPullRefusesRevokedBuilderKey(t *testing.T) {
	outDir, trustRoot, kp := buildLocalRepoWithBundle(t)
	publishRevocationList(t, outDir, kp, schema.RevocationList{
		Schema:             "polypkg.revocation-list/v1",
		Source:             "upstream",
		Serial:             1,
		Expires:            "2099-01-01T00:00:00Z",
		RevokedBuilderKeys: []string{"aa11bb22cc33dd44"},
	})
	stage := t.TempDir()
	_, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage})
	if err == nil {
		t.Fatal("expected refusal: pull must not carry forward an upstream-revoked builder key")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("error should name the revocation, got: %v", err)
	}
}

func TestPullSurfacesUpstreamRevokedSets(t *testing.T) {
	outDir, trustRoot, kp := buildLocalRepoWithCarried(t)
	revHash := "blake3:" + strings.Repeat("a1", 32)
	publishRevocationList(t, outDir, kp, schema.RevocationList{
		Schema:              "polypkg.revocation-list/v1",
		Source:              "upstream",
		Serial:              1,
		Expires:             "2999-01-01T00:00:00Z",
		RevokedAttestations: []string{revHash},
		RevokedBuilderKeys:  []string{"builder-unrelated"},
	})
	res, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if len(res.RevokedAttestations) != 1 || res.RevokedAttestations[0] != revHash {
		t.Fatalf("RevokedAttestations = %v, want [%s]", res.RevokedAttestations, revHash)
	}
	if len(res.RevokedBuilderKeys) != 1 || res.RevokedBuilderKeys[0] != "builder-unrelated" {
		t.Fatalf("RevokedBuilderKeys = %v", res.RevokedBuilderKeys)
	}
}

func TestPullSurfacesEmptyRevokedSetsWithNoUpstreamList(t *testing.T) {
	outDir, trustRoot, _ := buildLocalRepoWithCarried(t)
	res, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if res.RevokedAttestations != nil || res.RevokedBuilderKeys != nil {
		t.Fatalf("no upstream list must yield nil sets, got %v / %v", res.RevokedAttestations, res.RevokedBuilderKeys)
	}
}

func TestPullProceedsWithNoRevocationList(t *testing.T) {
	outDir, trustRoot, _ := buildLocalRepoWithCarried(t) // publishes no revocations.json
	stage := t.TempDir()
	if _, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage}); err != nil {
		t.Fatalf("pull with no revocation list published should succeed (absence is fine): %v", err)
	}
}

func TestPullStagesTrustBundleWhenPresent(t *testing.T) {
	outDir, trustRoot, _ := buildLocalRepoWithBundle(t)
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if res.TrustBundlePath == "" {
		t.Fatal("expected a staged trust bundle")
	}
	raw, err := os.ReadFile(res.TrustBundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := schema.ParseTrustBundle(bytesReader(raw)); err != nil {
		t.Fatalf("staged trust bundle is invalid: %v", err)
	}
}

func TestPullNoTrustBundleWhenAbsent(t *testing.T) {
	outDir, trustRoot := buildLocalRepo(t) // publishes none
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if res.TrustBundlePath != "" {
		t.Fatalf("expected no trust bundle, got %q", res.TrustBundlePath)
	}
}

// buildLocalRepoCarriedWithBundle builds a signed repo that carries BOTH a bound
// carried SLSA attestation (attestations/slsa.json → content/bin/hello) AND a
// published, repo-key-signed trust-bundle.json. It exercises the full carry
// pipeline in one round-trip: carried attestation carry-through plus trust-bundle
// carry-forward. Combines buildLocalRepoWithCarried and buildLocalRepoWithBundle.
func buildLocalRepoCarriedWithBundle(t *testing.T) (outDir, trustRoot string) {
	t.Helper()
	root := t.TempDir()
	keyDir := t.TempDir()
	pkgDir := filepath.Join(root, "pkgs", "hello")
	if err := os.MkdirAll(filepath.Join(pkgDir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "polypkg.yaml"),
		[]byte("schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	contentBytes := []byte("#!/bin/sh\necho hi\n")
	if err := os.WriteFile(filepath.Join(pkgDir, "content", "bin", "hello"), contentBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	// Bound carried SLSA: subject sha256 = the content file bytes, so repo.Build
	// binds it to content:bin/hello.
	sum := sha256.Sum256(contentBytes)
	attDir := filepath.Join(pkgDir, "attestations")
	if err := os.MkdirAll(attDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attDir, "slsa.json"),
		dsseSLSAInline("bin/hello", hex.EncodeToString(sum[:])), 0o644); err != nil {
		t.Fatal(err)
	}
	kp, err := repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "example.key")
	if err := repo.SaveKey(keyPath, kp, "pw", repo.KDFScrypt); err != nil {
		t.Fatal(err)
	}
	manifest := "schema: polypkg.repo/v1\nsource: upstream\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    source: ./pkgs/hello\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(repo.BuildOptions{}); err != nil {
		t.Fatalf("build carried+bundle fixture repo: %v", err)
	}
	outDir = filepath.Join(root, "public")
	trustRoot = filepath.Join(outDir, "trust_root.pub")

	// Publish a repo-key-signed trust bundle so Pull stages it for carry-forward.
	tb := schema.TrustBundle{
		Schema:  "polypkg.trust-bundle/v1",
		Source:  "upstream",
		Serial:  1,
		Expires: "2099-01-01T00:00:00Z",
		BuilderKeys: []schema.BuilderKey{{
			KeyID: "aa11bb22cc33dd44", PublicKey: "QUJDRA==", Algo: "ed25519", ValidFrom: "2020-01-01T00:00:00Z",
		}},
	}
	raw, err := json.Marshal(&tb)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "trust-bundle.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	sig := kp.SignTrustBundle(1, raw)
	if err := os.WriteFile(filepath.Join(outDir, "trust-bundle.json.minisig"), []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
	return outDir, trustRoot
}

// TestPullRoundTripsThroughRepoBuild proves the network pull's staged output
// (2e-3b) is a valid input to `repo build`'s prebuilt ingest (2e-3a): pull →
// WritePrebuiltManifest → repo build re-publishes a repo that (a) re-binds the
// carried attestation, (b) carries the artifact byte-identically, and (c) carries
// the trust bundle forward under the LOCAL key.
func TestPullRoundTripsThroughRepoBuild(t *testing.T) {
	outDir, trustRoot := buildLocalRepoCarriedWithBundle(t)
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if res.TrustBundlePath == "" {
		t.Fatal("expected the upstream trust bundle to be staged for carry-forward")
	}

	// Re-publish locally: fresh key + output, generate manifest, build (2e-3a ingest).
	keyDir := t.TempDir()
	kp, err := repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "local.key")
	if err := repo.SaveKey(keyPath, kp, "pw", repo.KDFScrypt); err != nil {
		t.Fatal(err)
	}
	localOut := filepath.Join(stage, "republished")
	mPath := filepath.Join(stage, "polypkg-repo.yaml")
	if err := WritePrebuiltManifest(mPath, PrebuiltManifestParams{
		Source: "local", Output: localOut, KeyPath: keyPath, KeyKDF: "scrypt",
	}, res); err != nil {
		t.Fatal(err)
	}
	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("new builder on pulled manifest: %v", err)
	}
	if _, err := b.Build(repo.BuildOptions{}); err != nil {
		t.Fatalf("repo build (ingest) on the pulled manifest failed: %v", err)
	}

	// (a) The re-published index carries a re-bound carried attestation.
	idxRaw, err := os.ReadFile(filepath.Join(localOut, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(idxRaw), "carried-opaque") {
		t.Fatalf("re-published index missing the re-bound carried attestation:\n%s", idxRaw)
	}

	// (b) The re-published artifact is byte-identical to what we pulled (verbatim ingest).
	pulledArt, err := os.ReadFile(res.Packages[0].ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	poolBlob := filepath.Join(localOut, "pool", strings.TrimPrefix(res.Packages[0].ContentHash, "blake3:")+".tar.zst")
	republished, err := os.ReadFile(poolBlob)
	if err != nil {
		t.Fatalf("re-published pool artifact missing: %v", err)
	}
	if !bytes.Equal(pulledArt, republished) {
		t.Fatal("re-published artifact is not byte-identical to the pulled artifact (ingest re-packed?)")
	}

	// (c) The re-published repo carried the trust bundle forward under the LOCAL key.
	if _, err := os.Stat(filepath.Join(localOut, "trust-bundle.json")); err != nil {
		t.Fatalf("re-published repo did not carry the trust bundle forward: %v", err)
	}
}

func TestWritePrebuiltManifestIsBuildable(t *testing.T) {
	outDir, trustRoot, _ := buildLocalRepoWithCarried(t)
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage})
	if err != nil {
		t.Fatal(err)
	}
	mPath := filepath.Join(stage, "polypkg-repo.yaml")
	if err := WritePrebuiltManifest(mPath, PrebuiltManifestParams{
		Source: "local", Output: filepath.Join(stage, "out"), KeyPath: "/keys/local.key", KeyKDF: "scrypt",
	}, res); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(mPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := schema.ParseRepoManifest(f)
	if err != nil {
		t.Fatalf("generated manifest invalid: %v", err)
	}
	pk, ok := m.Packages["hello"]
	if !ok || pk.Prebuilt == nil {
		t.Fatalf("generated manifest missing hello.prebuilt: %+v", m.Packages)
	}
}

func TestWritePrebuiltManifestMultiMergesSourcesWithPerSourceBundles(t *testing.T) {
	res1 := &PullResult{
		Packages:        []PulledPackage{{Name: "foo", Version: "1.0.0", ArtifactPath: "/s1/foo.tar.zst", AttDir: "/s1/atts"}},
		TrustBundlePath: "/s1/trust-bundle.json",
	}
	res2 := &PullResult{
		Packages:        []PulledPackage{{Name: "bar", Version: "2.0.0", ArtifactPath: "/s2/bar.tar.zst", AttDir: "/s2/atts"}},
		TrustBundlePath: "/s2/trust-bundle.json",
	}
	mPath := filepath.Join(t.TempDir(), "polypkg-repo.yaml")
	if err := WritePrebuiltManifestMulti(mPath, PrebuiltManifestParams{
		Source: "local", Output: "/out", KeyPath: "/k.key", KeyKDF: "scrypt",
	}, []*PullResult{res1, res2}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(mPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{
		"foo:\n    prebuilt:\n      artifact: /s1/foo.tar.zst\n      attestations: /s1/atts\n      trust_bundle: /s1/trust-bundle.json\n",
		"bar:\n    prebuilt:\n      artifact: /s2/bar.tar.zst\n      attestations: /s2/atts\n      trust_bundle: /s2/trust-bundle.json\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("manifest missing block %q:\n%s", want, got)
		}
	}
}

func TestWritePrebuiltManifestMultiRejectsDuplicatePackageName(t *testing.T) {
	res1 := &PullResult{Packages: []PulledPackage{{Name: "foo", Version: "1.0.0", ArtifactPath: "/s1/foo.tar.zst", AttDir: "/s1/atts"}}}
	res2 := &PullResult{Packages: []PulledPackage{{Name: "foo", Version: "9.0.0", ArtifactPath: "/s2/foo.tar.zst", AttDir: "/s2/atts"}}}
	err := WritePrebuiltManifestMulti(filepath.Join(t.TempDir(), "m.yaml"), PrebuiltManifestParams{
		Source: "local", Output: "/out", KeyPath: "/k.key", KeyKDF: "scrypt",
	}, []*PullResult{res1, res2})
	if err == nil || !strings.Contains(err.Error(), "more than one source") {
		t.Fatalf("want cross-source duplicate-name error, got %v", err)
	}
}

func TestStagedPkgDirNoDelimiterCollision(t *testing.T) {
	root := t.TempDir()
	a, err := stagedPkgDir(root, "a", "b-1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	b, err := stagedPkgDir(root, "a-b", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("distinct packages collide on the same staging dir: %q", a)
	}
}

// writeIndexJSON writes a minimal signed-shape index.json into dir for the
// WriteManagementManifest tests. Only the fields the manifest emitter reads
// matter; the document is never signature-checked here.
func writeIndexJSON(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWriteManagementManifestUsesAbsolutePublishedPaths(t *testing.T) {
	out := filepath.Join(t.TempDir(), "mirror")
	writeIndexJSON(t, out, `{"schema":"polypkg.index/v2","expires":"2030-01-01T00:00:00Z","packages":{"hello":[{"version":"1.0.0","content_hash":"blake3:aa","artifact":"pool/aa.tar.zst","revision":1}]}}`)
	if err := os.WriteFile(filepath.Join(out, "trust-bundle.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := WriteManagementManifest(PrebuiltManifestParams{
		Source: "mymirror", Output: out, KeyPath: filepath.Join(t.TempDir(), "local.key"), KeyKDF: "scrypt",
	})
	if err != nil {
		t.Fatalf("WriteManagementManifest: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(out, ManagementManifestName))
	if err != nil {
		t.Fatalf("manifest not written: %v", err)
	}
	m, perr := schema.ParseRepoManifest(bytesReader(raw))
	if perr != nil {
		t.Fatalf("emitted manifest fails schema parse: %v\n%s", perr, raw)
	}
	if m.Source != "mymirror" {
		t.Errorf("source = %q, want mymirror", m.Source)
	}
	if !filepath.IsAbs(m.Output) || !filepath.IsAbs(m.Key.Path) {
		t.Errorf("output (%q) and key.path (%q) must both be absolute", m.Output, m.Key.Path)
	}
	pkg, ok := m.Packages["hello"]
	if !ok || pkg.Prebuilt == nil {
		t.Fatalf("emitted manifest has no prebuilt entry for hello: %+v", m.Packages)
	}
	wantArtifact := filepath.Join(out, "pool", "aa.tar.zst")
	if pkg.Prebuilt.Artifact != wantArtifact {
		t.Errorf("artifact = %q, want the published pool blob %q", pkg.Prebuilt.Artifact, wantArtifact)
	}
	if pkg.Prebuilt.Attestations != filepath.Join(out, "pool") {
		t.Errorf("attestations = %q, want the published pool dir", pkg.Prebuilt.Attestations)
	}
	if pkg.Prebuilt.TrustBundle != filepath.Join(out, "trust-bundle.json") {
		t.Errorf("trust_bundle = %q, want the published bundle", pkg.Prebuilt.TrustBundle)
	}
}

// A --fresh mirror publishes no trust bundle; the manifest must not reference
// one that does not exist (repo build would refuse to open it).
func TestWriteManagementManifestOmitsAbsentTrustBundle(t *testing.T) {
	out := filepath.Join(t.TempDir(), "mirror")
	writeIndexJSON(t, out, `{"schema":"polypkg.index/v2","expires":"2030-01-01T00:00:00Z","packages":{"hello":[{"version":"1.0.0","content_hash":"blake3:aa","artifact":"pool/aa.tar.zst","revision":1}]}}`)

	if err := WriteManagementManifest(PrebuiltManifestParams{
		Source: "mymirror", Output: out, KeyPath: filepath.Join(t.TempDir(), "local.key"), KeyKDF: "scrypt",
	}); err != nil {
		t.Fatalf("WriteManagementManifest: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(out, ManagementManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "trust_bundle") {
		t.Fatalf("manifest references an absent trust bundle:\n%s", raw)
	}
}

func TestWriteManagementManifestRefusesWithoutPublishedIndex(t *testing.T) {
	out := t.TempDir()
	err := WriteManagementManifest(PrebuiltManifestParams{
		Source: "mymirror", Output: out, KeyPath: filepath.Join(t.TempDir(), "local.key"), KeyKDF: "scrypt",
	})
	if err == nil {
		t.Fatal("expected an error when no index.json has been published")
	}
	if !strings.Contains(err.Error(), "read published index") {
		t.Fatalf("error = %v, want it to name the missing index", err)
	}
}

// A repo manifest holds exactly one prebuilt per package name. An index that
// lists two versions of a name cannot be expressed, so refuse rather than pick.
func TestWriteManagementManifestRefusesMultiVersionPackage(t *testing.T) {
	out := filepath.Join(t.TempDir(), "mirror")
	writeIndexJSON(t, out, `{"schema":"polypkg.index/v2","expires":"2030-01-01T00:00:00Z","packages":{"hello":[{"version":"1.0.0","content_hash":"blake3:aa","artifact":"pool/aa.tar.zst","revision":1},{"version":"2.0.0","content_hash":"blake3:bb","artifact":"pool/bb.tar.zst","revision":1}]}}`)

	err := WriteManagementManifest(PrebuiltManifestParams{
		Source: "mymirror", Output: out, KeyPath: filepath.Join(t.TempDir(), "local.key"), KeyKDF: "scrypt",
	})
	if err == nil {
		t.Fatal("expected an error for a package with two published versions")
	}
	if !strings.Contains(err.Error(), "one prebuilt per name") {
		t.Fatalf("error = %v, want it to explain the one-version constraint", err)
	}
	if _, statErr := os.Stat(filepath.Join(out, ManagementManifestName)); statErr == nil {
		t.Fatal("a refused emit still wrote a manifest")
	}
}
