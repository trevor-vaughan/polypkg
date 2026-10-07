package mirror

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
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
		"packages:\n  hello:\n    - source: ./pkgs/hello\n"
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

// buildLocalRepoTwoVersions builds an upstream publishing hello 1.0.0 and
// 1.1.0, and returns its public dir and trust root. Mirrors buildLocalRepo,
// which publishes a single version.
func buildLocalRepoTwoVersions(t *testing.T) (outDir, trustRoot string) {
	t.Helper()
	root := t.TempDir()
	keyDir := t.TempDir()

	for _, v := range []string{"1.0.0", "1.1.0"} {
		dir := filepath.Join(root, "pkgs", "hello-"+v)
		if err := os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		pm := "schema: polypkg.package/v1\nname: hello\nversion: " + v + "\nactions: []\n"
		if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(pm), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "content", "bin", "hi"),
			[]byte("#!/bin/sh\necho "+v+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
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
		"packages:\n  hello:\n    - source: ./pkgs/hello-1.0.0\n    - source: ./pkgs/hello-1.1.0\n"
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
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir(),
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
		URL: outDir, TrustRoot: otherRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir(),
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
		"packages:\n  hello:\n    - source: ./pkgs/hello\n"
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
	res, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir()})
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
	if _, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir()}); err == nil {
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
	if _, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir()}); err == nil {
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
	got, _, err := resolvePullSelection(idx, []string{"foo"}, false)
	if err != nil || len(got) != 1 || got[0].version != "2.0.0" {
		t.Fatalf("bare name: got %+v err %v, want foo@2.0.0", got, err)
	}
	// name@version → exact
	got, _, err = resolvePullSelection(idx, []string{"foo@1.0.0"}, false)
	if err != nil || len(got) != 1 || got[0].version != "1.0.0" {
		t.Fatalf("pinned: got %+v err %v, want foo@1.0.0", got, err)
	}
	// missing version → error
	if _, _, err := resolvePullSelection(idx, []string{"foo@9.9.9"}, false); err == nil {
		t.Fatal("expected error for missing version")
	}
	// duplicate name → error
	if _, _, err := resolvePullSelection(idx, []string{"foo", "foo@1.0.0"}, false); err == nil {
		t.Fatal("expected error for duplicate-name selection")
	}
}

// TestResolvePullSelectionMultipleVersionsSameName proves a coherent
// multi-version request works now that a repo manifest holds a list of
// versions per name: selecting two distinct versions of "hello" is not a
// conflict, it is two selections.
func TestResolvePullSelectionMultipleVersionsSameName(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"hello": {{Version: "1.0.0", ContentHash: "blake3:a"}, {Version: "1.1.0", ContentHash: "blake3:b"}},
	}}
	got, notes, err := resolvePullSelection(idx, []string{"hello@1.0.0", "hello@1.1.0"}, false)
	if err != nil {
		t.Fatalf("resolvePullSelection: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d selections, want 2: %+v", len(got), got)
	}
	haveVersion := map[string]bool{got[0].version: true, got[1].version: true}
	if !haveVersion["1.0.0"] || !haveVersion["1.1.0"] {
		t.Fatalf("selections = %+v, want both hello@1.0.0 and hello@1.1.0", got)
	}
	if len(notes) != 0 {
		t.Fatalf("notes = %v, want none (both versions explicitly selected)", notes)
	}
}

// TestResolvePullSelectionRefusesDuplicateVersion covers the still-genuine
// conflict: the same exact version named twice.
func TestResolvePullSelectionRefusesDuplicateVersion(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"hello": {{Version: "1.0.0", ContentHash: "blake3:a"}},
	}}
	if _, _, err := resolvePullSelection(idx, []string{"hello@1.0.0", "hello@1.0.0"}, false); err == nil {
		t.Fatal("expected refusal: the same name@version selected twice")
	}
}

// TestResolvePullSelectionRefusesDuplicateBareName covers the same bare
// selector repeated, which is also unambiguous but still a duplicate.
func TestResolvePullSelectionRefusesDuplicateBareName(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"hello": {{Version: "1.0.0", ContentHash: "blake3:a"}},
	}}
	if _, _, err := resolvePullSelection(idx, []string{"hello", "hello"}, false); err == nil {
		t.Fatal("expected refusal: the same bare selector repeated")
	}
}

// TestResolvePullSelectionRefusesBarePlusVersioned covers genuine ambiguity:
// a bare selector means "latest", so pairing it with an explicit version of
// the same name does not resolve to a coherent request.
func TestResolvePullSelectionRefusesBarePlusVersioned(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"hello": {{Version: "1.0.0", ContentHash: "blake3:a"}, {Version: "1.1.0", ContentHash: "blake3:b"}},
	}}
	_, _, err := resolvePullSelection(idx, []string{"hello", "hello@1.0.0"}, false)
	if err == nil {
		t.Fatal("expected refusal: bare name plus an explicit version of the same name")
	}
	if !strings.Contains(err.Error(), "latest") {
		t.Fatalf("error should explain the ambiguity (bare name means latest): %v", err)
	}
}

// TestPullAcceptsBothVersionsOfSameName is the end-to-end proof: pulling two
// distinct versions of the same package name from a real multi-version
// upstream must succeed and stage both. This fails before the Part 1 fix,
// because resolvePullSelection refused any name selected twice regardless of
// which version.
func TestPullAcceptsBothVersionsOfSameName(t *testing.T) {
	outDir, trustRoot := buildLocalRepoTwoVersions(t)
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir(),
		Selectors: []string{"hello@1.0.0", "hello@1.1.0"},
	})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(res.Packages) != 2 {
		t.Fatalf("pulled = %+v, want both hello@1.0.0 and hello@1.1.0", res.Packages)
	}
	gotVersions := map[string]bool{res.Packages[0].Version: true, res.Packages[1].Version: true}
	if !gotVersions["1.0.0"] || !gotVersions["1.1.0"] {
		t.Fatalf("pulled = %+v, want both hello@1.0.0 and hello@1.1.0", res.Packages)
	}
	if len(res.Narrowed) != 0 {
		t.Fatalf("Narrowed = %v, want none (operator explicitly chose both versions)", res.Narrowed)
	}
}

// TestPullEmptySelectorsNarrowsMultiVersionUpstream proves that pulling "all
// packages, latest of each" against an upstream with more than one version of
// a name produces an actionable note naming what got left behind, instead of
// silently narrowing the mirror.
func TestPullEmptySelectorsNarrowsMultiVersionUpstream(t *testing.T) {
	outDir, trustRoot := buildLocalRepoTwoVersions(t)
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Version != "1.1.0" {
		t.Fatalf("pulled = %+v, want only hello@1.1.0 (latest)", res.Packages)
	}
	if len(res.Narrowed) != 1 {
		t.Fatalf("Narrowed = %v, want exactly one note", res.Narrowed)
	}
	note := res.Narrowed[0]
	if !strings.Contains(note, "hello") || !strings.Contains(note, "1.1.0") || !strings.Contains(note, "1.0.0") {
		t.Fatalf("note = %q, want it to name hello, the mirrored version 1.1.0, and the skipped version 1.0.0", note)
	}
}

// TestPullBareNameNarrowsMultiVersionUpstream covers the same silent-latest
// pick via an explicit bare selector rather than the empty-selectors case.
func TestPullBareNameNarrowsMultiVersionUpstream(t *testing.T) {
	outDir, trustRoot := buildLocalRepoTwoVersions(t)
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir(),
		Selectors: []string{"hello"},
	})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(res.Narrowed) != 1 {
		t.Fatalf("Narrowed = %v, want exactly one note", res.Narrowed)
	}
	note := res.Narrowed[0]
	if !strings.Contains(note, "hello") || !strings.Contains(note, "1.1.0") || !strings.Contains(note, "1.0.0") {
		t.Fatalf("note = %q, want it to name hello, the mirrored version 1.1.0, and the skipped version 1.0.0", note)
	}
}

// TestPullExplicitVersionProducesNoNarrowingNote proves an operator who pins
// an exact version never gets a narrowing note: they chose explicitly, there
// is nothing silent about it.
func TestPullExplicitVersionProducesNoNarrowingNote(t *testing.T) {
	outDir, trustRoot := buildLocalRepoTwoVersions(t)
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir(),
		Selectors: []string{"hello@1.0.0"},
	})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(res.Narrowed) != 0 {
		t.Fatalf("Narrowed = %v, want none (operator explicitly chose the version)", res.Narrowed)
	}
}

// TestPullSingleVersionUpstreamProducesNoNarrowingNote proves an upstream
// that only ever published one version never triggers a note: there is
// nothing to narrow away.
func TestPullSingleVersionUpstreamProducesNoNarrowingNote(t *testing.T) {
	outDir, trustRoot := buildLocalRepo(t)
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(res.Narrowed) != 0 {
		t.Fatalf("Narrowed = %v, want none (upstream has only one version)", res.Narrowed)
	}
}

// TestResolvePullSelectionAllVersionsNoSelectors proves --all-versions with no
// selectors mirrors every version of every package instead of only the
// latest, and that resolving under it never produces a narrowing note —
// nothing was left behind, so there is nothing to report.
func TestResolvePullSelectionAllVersionsNoSelectors(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"hello": {{Version: "1.0.0", ContentHash: "blake3:a"}, {Version: "1.1.0", ContentHash: "blake3:b"}},
	}}
	got, notes, err := resolvePullSelection(idx, nil, true)
	if err != nil {
		t.Fatalf("resolvePullSelection: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d selections, want 2: %+v", len(got), got)
	}
	haveVersion := map[string]bool{got[0].version: true, got[1].version: true}
	if !haveVersion["1.0.0"] || !haveVersion["1.1.0"] {
		t.Fatalf("selections = %+v, want both hello@1.0.0 and hello@1.1.0", got)
	}
	if len(notes) != 0 {
		t.Fatalf("notes = %v, want none (--all-versions dropped nothing)", notes)
	}
}

// TestResolvePullSelectionAllVersionsBareName covers the same widening via an
// explicit bare "--package hello" rather than empty selectors.
func TestResolvePullSelectionAllVersionsBareName(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"hello": {{Version: "1.0.0", ContentHash: "blake3:a"}, {Version: "1.1.0", ContentHash: "blake3:b"}},
	}}
	got, notes, err := resolvePullSelection(idx, []string{"hello"}, true)
	if err != nil {
		t.Fatalf("resolvePullSelection: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d selections, want 2: %+v", len(got), got)
	}
	if len(notes) != 0 {
		t.Fatalf("notes = %v, want none (--all-versions dropped nothing)", notes)
	}
}

// TestResolvePullSelectionAllVersionsExplicitPinWins proves --all-versions
// does not override an explicit pin: "hello@1.0.0" is already unambiguous, so
// it still resolves to exactly that one version.
func TestResolvePullSelectionAllVersionsExplicitPinWins(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"hello": {{Version: "1.0.0", ContentHash: "blake3:a"}, {Version: "1.1.0", ContentHash: "blake3:b"}},
	}}
	got, notes, err := resolvePullSelection(idx, []string{"hello@1.0.0"}, true)
	if err != nil {
		t.Fatalf("resolvePullSelection: %v", err)
	}
	if len(got) != 1 || got[0].version != "1.0.0" {
		t.Fatalf("got %+v, want exactly hello@1.0.0", got)
	}
	if len(notes) != 0 {
		t.Fatalf("notes = %v, want none (explicit pin, not a latest resolution)", notes)
	}
}

// TestResolvePullSelectionAllVersionsRefusesDuplicateBareName proves the
// existing duplicate guard still applies under --all-versions: the same bare
// selector repeated is still a duplicate, not "select all versions twice".
func TestResolvePullSelectionAllVersionsRefusesDuplicateBareName(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"hello": {{Version: "1.0.0", ContentHash: "blake3:a"}, {Version: "1.1.0", ContentHash: "blake3:b"}},
	}}
	if _, _, err := resolvePullSelection(idx, []string{"hello", "hello"}, true); err == nil {
		t.Fatal("expected refusal: the same bare selector repeated, even under --all-versions")
	}
}

// TestPullAllVersionsSingleVersionUpstreamNoNotes proves --all-versions
// against an upstream that only ever published one version mirrors that one
// version and produces no narrowing note (there was nothing to widen).
func TestPullAllVersionsSingleVersionUpstreamNoNotes(t *testing.T) {
	outDir, trustRoot := buildLocalRepo(t)
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir(),
		AllVersions: true,
	})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(res.Packages) != 1 {
		t.Fatalf("pulled = %+v, want exactly one package", res.Packages)
	}
	if len(res.Narrowed) != 0 {
		t.Fatalf("Narrowed = %v, want none (upstream has only one version)", res.Narrowed)
	}
}

// TestPullAllVersionsStagesBothVersionsAndManifestCarriesBoth is the
// end-to-end proof: --all-versions against a real multi-version upstream
// stages every version, and the manifest WritePrebuiltManifestMulti emits
// from the result carries every version too. Parsed through
// schema.ParseRepoManifest rather than substring-matched, so a duplicate
// mapping key or bad indentation is caught — an earlier round of this work
// shipped a duplicate "hello:" key that substring assertions sailed past.
func TestPullAllVersionsStagesBothVersionsAndManifestCarriesBoth(t *testing.T) {
	outDir, trustRoot := buildLocalRepoTwoVersions(t)
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir(),
		AllVersions: true,
	})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(res.Packages) != 2 {
		t.Fatalf("pulled = %+v, want both hello@1.0.0 and hello@1.1.0", res.Packages)
	}
	gotVersions := map[string]bool{res.Packages[0].Version: true, res.Packages[1].Version: true}
	if !gotVersions["1.0.0"] || !gotVersions["1.1.0"] {
		t.Fatalf("pulled = %+v, want both hello@1.0.0 and hello@1.1.0", res.Packages)
	}
	if len(res.Narrowed) != 0 {
		t.Fatalf("Narrowed = %v, want none (--all-versions dropped nothing)", res.Narrowed)
	}

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
	if err := WritePrebuiltManifestMulti(mPath, PrebuiltManifestParams{
		Source: "local", Output: localOut, KeyPath: keyPath, KeyKDF: "scrypt",
	}, []*PullResult{res}); err != nil {
		t.Fatal(err)
	}
	mRaw, err := os.ReadFile(mPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, perr := schema.ParseRepoManifest(bytesReader(mRaw))
	if perr != nil {
		t.Fatalf("emitted manifest fails schema parse (duplicate YAML key?): %v\n%s", perr, mRaw)
	}
	pk, ok := manifest.Packages["hello"]
	if !ok || len(pk) != 2 {
		t.Fatalf("manifest carries %d entries for hello, want 2: %+v", len(pk), manifest.Packages["hello"])
	}
	if pk[0].Prebuilt == nil || pk[1].Prebuilt == nil {
		t.Fatalf("both hello entries must be prebuilt: %+v", pk)
	}
	if pk[0].Prebuilt.Artifact == pk[1].Prebuilt.Artifact {
		t.Fatalf("both hello entries point at the same artifact %q; distinct versions must publish distinct pool blobs", pk[0].Prebuilt.Artifact)
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
		"packages:\n  hello:\n    - source: ./pkgs/hello\n"
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
	_, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir()})
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
	_, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir()})
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
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(), StateHome: t.TempDir(),
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
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(), StateHome: t.TempDir(),
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
	if _, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir()}); err != nil {
		t.Fatalf("pull with no revocation list published should succeed (absence is fine): %v", err)
	}
}

func TestPullStagesTrustBundleWhenPresent(t *testing.T) {
	outDir, trustRoot, _ := buildLocalRepoWithBundle(t)
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir()})
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
	res, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir()})
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
		"packages:\n  hello:\n    - source: ./pkgs/hello\n"
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
	res, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir()})
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
	res, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir()})
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
	if !ok || len(pk) != 1 || pk[0].Prebuilt == nil {
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
		"foo:\n    - prebuilt:\n        artifact: /s1/foo.tar.zst\n        attestations: /s1/atts\n        trust_bundle: /s1/trust-bundle.json\n",
		"bar:\n    - prebuilt:\n        artifact: /s2/bar.tar.zst\n        attestations: /s2/atts\n        trust_bundle: /s2/trust-bundle.json\n",
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

// TestWritePrebuiltManifestMultiKeepsAllVersionsFromOneSource pulls two real,
// separately-staged versions of "hello" from the SAME upstream (two Pull calls
// against one source, merged into one PullResult the way a caller assembling a
// single source's selections would) and proves WritePrebuiltManifestMulti does
// NOT treat them as a cross-source collision, and emits "hello:" exactly once
// with two "- prebuilt:" list items rather than a duplicated YAML mapping key.
func TestWritePrebuiltManifestMultiKeepsAllVersionsFromOneSource(t *testing.T) {
	outDir, trustRoot := buildLocalRepoTwoVersions(t)
	stage := t.TempDir()
	r1, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream",
		Selectors: []string{"hello@1.0.0"}, StageDir: filepath.Join(stage, "v1"), StateHome: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream",
		Selectors: []string{"hello@1.1.0"}, StageDir: filepath.Join(stage, "v2"), StateHome: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	merged := &PullResult{Packages: append(append([]PulledPackage{}, r1.Packages...), r2.Packages...)}

	mPath := filepath.Join(stage, "polypkg-repo.yaml")
	if err := WritePrebuiltManifestMulti(mPath, PrebuiltManifestParams{
		Source: "local", Output: filepath.Join(stage, "out"), KeyPath: "/keys/local.key", KeyKDF: "scrypt",
	}, []*PullResult{merged}); err != nil {
		t.Fatalf("two versions of one name from the SAME source must not collide: %v", err)
	}

	f, err := os.Open(mPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := schema.ParseRepoManifest(f)
	if err != nil {
		t.Fatalf("generated manifest invalid (duplicate YAML key?): %v\npath: %s", err, mPath)
	}
	pk, ok := m.Packages["hello"]
	if !ok || len(pk) != 2 {
		t.Fatalf("want 2 prebuilt entries for hello, got %+v", m.Packages["hello"])
	}
	if pk[0].Prebuilt == nil || pk[0].Prebuilt.Artifact != r1.Packages[0].ArtifactPath {
		t.Errorf("entry 0 artifact = %+v, want %q (1.0.0)", pk[0].Prebuilt, r1.Packages[0].ArtifactPath)
	}
	if pk[1].Prebuilt == nil || pk[1].Prebuilt.Artifact != r2.Packages[0].ArtifactPath {
		t.Errorf("entry 1 artifact = %+v, want %q (1.1.0)", pk[1].Prebuilt, r2.Packages[0].ArtifactPath)
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
	if !ok || len(pkg) != 1 || pkg[0].Prebuilt == nil {
		t.Fatalf("emitted manifest has no prebuilt entry for hello: %+v", m.Packages)
	}
	wantArtifact := filepath.Join(out, "pool", "aa.tar.zst")
	if pkg[0].Prebuilt.Artifact != wantArtifact {
		t.Errorf("artifact = %q, want the published pool blob %q", pkg[0].Prebuilt.Artifact, wantArtifact)
	}
	if pkg[0].Prebuilt.Attestations != filepath.Join(out, "pool") {
		t.Errorf("attestations = %q, want the published pool dir", pkg[0].Prebuilt.Attestations)
	}
	if pkg[0].Prebuilt.TrustBundle != filepath.Join(out, "trust-bundle.json") {
		t.Errorf("trust_bundle = %q, want the published bundle", pkg[0].Prebuilt.TrustBundle)
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

// A repo manifest holds a LIST of prebuilts per package name (one per
// published version), so a published index listing two versions of a name
// must emit two "- prebuilt:" list items under one "hello:" key, not an error.
func TestWriteManagementManifestEmitsOnePrebuiltPerPublishedVersion(t *testing.T) {
	out := filepath.Join(t.TempDir(), "mirror")
	writeIndexJSON(t, out, `{"schema":"polypkg.index/v2","expires":"2030-01-01T00:00:00Z","packages":{"hello":[{"version":"1.0.0","content_hash":"blake3:aa","artifact":"pool/aa.tar.zst","revision":1},{"version":"1.1.0","content_hash":"blake3:bb","artifact":"pool/bb.tar.zst","revision":1}]}}`)
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
		t.Fatal(err)
	}
	m, perr := schema.ParseRepoManifest(bytesReader(raw))
	if perr != nil {
		t.Fatalf("emitted manifest fails schema parse (duplicate YAML key?): %v\n%s", perr, raw)
	}
	pkg, ok := m.Packages["hello"]
	if !ok || len(pkg) != 2 {
		t.Fatalf("want 2 prebuilt entries for hello, got %+v", m.Packages["hello"])
	}
	wantArt0 := filepath.Join(out, "pool", "aa.tar.zst")
	wantArt1 := filepath.Join(out, "pool", "bb.tar.zst")
	if pkg[0].Prebuilt == nil || pkg[0].Prebuilt.Artifact != wantArt0 {
		t.Errorf("entry 0 artifact = %+v, want %q", pkg[0].Prebuilt, wantArt0)
	}
	if pkg[1].Prebuilt == nil || pkg[1].Prebuilt.Artifact != wantArt1 {
		t.Errorf("entry 1 artifact = %+v, want %q", pkg[1].Prebuilt, wantArt1)
	}
}

// TestPullTwoVersionsSurviveMirrorRepublish is the real end-to-end path: pull
// two real, separately-staged versions of "hello" from one upstream, merge
// them into a single source's PullResult, write the prebuilt manifest, run
// them through `repo build` (the actual ingest path production code uses),
// then regenerate the management manifest from what was actually published.
// Both versions must survive every hop.
func TestPullTwoVersionsSurviveMirrorRepublish(t *testing.T) {
	outDir, trustRoot := buildLocalRepoTwoVersions(t)
	stage := t.TempDir()
	r1, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream",
		Selectors: []string{"hello@1.0.0"}, StageDir: filepath.Join(stage, "v1"), StateHome: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream",
		Selectors: []string{"hello@1.1.0"}, StageDir: filepath.Join(stage, "v2"), StateHome: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	merged := &PullResult{Packages: append(append([]PulledPackage{}, r1.Packages...), r2.Packages...)}

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
	if err := WritePrebuiltManifestMulti(mPath, PrebuiltManifestParams{
		Source: "local", Output: localOut, KeyPath: keyPath, KeyKDF: "scrypt",
	}, []*PullResult{merged}); err != nil {
		t.Fatal(err)
	}
	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("new builder on the pulled manifest: %v", err)
	}
	if _, err := b.Build(repo.BuildOptions{}); err != nil {
		t.Fatalf("repo build (ingest) on the pulled manifest failed: %v", err)
	}

	// The published index carries both versions forward.
	idxRaw, err := os.ReadFile(filepath.Join(localOut, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	idx, err := schema.ParseIndex(bytesReader(idxRaw))
	if err != nil {
		t.Fatalf("published index invalid: %v", err)
	}
	if len(idx.Packages["hello"]) != 2 {
		t.Fatalf("published index carries %d version(s) of hello, want 2:\n%s", len(idx.Packages["hello"]), idxRaw)
	}

	// Regenerating the management manifest from the published index emits both
	// versions as list items under one "hello:" key rather than erroring or
	// emitting a duplicate mapping key.
	if err := WriteManagementManifest(PrebuiltManifestParams{
		Source: "local", Output: localOut, KeyPath: keyPath, KeyKDF: "scrypt",
	}); err != nil {
		t.Fatalf("WriteManagementManifest: %v", err)
	}
	mgmtRaw, err := os.ReadFile(filepath.Join(localOut, ManagementManifestName))
	if err != nil {
		t.Fatal(err)
	}
	mgmt, perr := schema.ParseRepoManifest(bytesReader(mgmtRaw))
	if perr != nil {
		t.Fatalf("management manifest fails schema parse (duplicate YAML key?): %v\n%s", perr, mgmtRaw)
	}
	pk, ok := mgmt.Packages["hello"]
	if !ok || len(pk) != 2 {
		t.Fatalf("management manifest carries %d prebuilt(s) for hello, want 2: %+v", len(pk), mgmt.Packages["hello"])
	}
	if pk[0].Prebuilt == nil || pk[1].Prebuilt == nil {
		t.Fatalf("both hello entries must be prebuilt: %+v", pk)
	}
	if pk[0].Prebuilt.Artifact == pk[1].Prebuilt.Artifact {
		t.Fatalf("both hello entries point at the same artifact %q; distinct versions must publish distinct pool blobs", pk[0].Prebuilt.Artifact)
	}
}

// buildUpstreamWithAllDocs builds an upstream that publishes all four signed
// documents a pull verifies: the trust document and index (serials minted by
// repo build), a trust bundle at serial 1 (buildLocalRepoWithBundle), and a
// revocation list at serial 3. The revocation list revokes only a builder key
// that the bundle does not carry, so the pull itself succeeds.
func buildUpstreamWithAllDocs(t *testing.T) (outDir, trustRoot string) {
	t.Helper()
	outDir, trustRoot, kp := buildLocalRepoWithBundle(t)
	publishRevocationList(t, outDir, kp, schema.RevocationList{
		Schema:             "polypkg.revocation-list/v1",
		Source:             "upstream",
		Serial:             3,
		Expires:            "2099-01-01T00:00:00Z",
		RevokedBuilderKeys: []string{"builder-unrelated"},
	})
	return outDir, trustRoot
}

func TestPullReportsVerifiedFloorsWithoutPersistingThem(t *testing.T) {
	outDir, trustRoot := buildUpstreamWithAllDocs(t)
	stateHome := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(), StateHome: stateHome,
	})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if !strings.HasPrefix(res.SeenKey, "upstream.") || len(res.SeenKey) != len("upstream.")+16 {
		t.Fatalf("SeenKey = %q, want upstream.<16-hex trust-root key id>", res.SeenKey)
	}
	if res.Seen.TrustSerial == 0 || res.Seen.IndexSerial == 0 {
		t.Fatalf("trust/index serials not reported: %+v", res.Seen)
	}
	if res.Seen.BundleSerial != 1 || res.Seen.RevocationSerial != 3 {
		t.Fatalf("bundle/revocation serials = %d/%d, want 1/3", res.Seen.BundleSerial, res.Seen.RevocationSerial)
	}
	names, err := trust.ListSeenSources(stateHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("Pull persisted floors itself (%v); only the caller may, after the whole mirror run succeeds", names)
	}
}

func TestPullKeysStateBySourceNameAndTrustRoot(t *testing.T) {
	outA, rootA := buildLocalRepo(t)
	outB, rootB := buildLocalRepo(t) // same signed source name "upstream", different key
	a, err := Pull(context.Background(), PullOptions{URL: outA, TrustRoot: rootA, SourceName: "upstream", StageDir: t.TempDir(), StateHome: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Pull(context.Background(), PullOptions{URL: outB, TrustRoot: rootB, SourceName: "upstream", StageDir: t.TempDir(), StateHome: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if a.SeenKey == b.SeenKey {
		t.Fatalf("two upstreams with different trust roots share state key %q; one would wedge the other's floors", a.SeenKey)
	}
}

func TestPullAcceptsUnchangedUpstreamAtStoredFloors(t *testing.T) {
	outDir, trustRoot := buildUpstreamWithAllDocs(t)
	stateHome := t.TempDir()
	first, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(), StateHome: stateHome})
	if err != nil {
		t.Fatalf("first pull: %v", err)
	}
	if err := trust.StoreSeen(stateHome, first.SeenKey, first.Seen); err != nil {
		t.Fatal(err)
	}
	second, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(), StateHome: stateHome})
	if err != nil {
		t.Fatalf("re-pull of an unchanged upstream at its own floors must succeed: %v", err)
	}
	if second.Seen.TrustSerial != first.Seen.TrustSerial || second.Seen.IndexSerial != first.Seen.IndexSerial ||
		second.Seen.BundleSerial != first.Seen.BundleSerial || second.Seen.RevocationSerial != first.Seen.RevocationSerial {
		t.Fatalf("floors changed on an unchanged upstream: first %+v, second %+v", first.Seen, second.Seen)
	}
}

// A stored floor one above the served serial is exactly the state a mirror is in
// when an attacker replays an older (still unexpired) signed document.
func TestPullRefusesRollbackOfEachSignedDocument(t *testing.T) {
	outDir, trustRoot := buildUpstreamWithAllDocs(t)
	baseline, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(), StateHome: t.TempDir()})
	if err != nil {
		t.Fatalf("baseline pull: %v", err)
	}
	cur := baseline.Seen
	for _, tc := range []struct {
		doc  string
		bump func(s *trust.Seen)
		want string
	}{
		{"trust document", func(s *trust.Seen) { s.TrustSerial++ },
			fmt.Sprintf("trust document rollback: serial %d is below last-seen %d", cur.TrustSerial, cur.TrustSerial+1)},
		{"index", func(s *trust.Seen) { s.IndexSerial++ },
			fmt.Sprintf("index rollback: serial %d is below last-seen %d", cur.IndexSerial, cur.IndexSerial+1)},
		{"trust bundle", func(s *trust.Seen) { s.BundleSerial++ },
			"trust bundle rollback: serial 1 is below last-seen 2"},
		{"revocation list", func(s *trust.Seen) { s.RevocationSerial++ },
			"revocation list rollback: serial 3 is below last-seen 4"},
	} {
		t.Run(tc.doc, func(t *testing.T) {
			stateHome := t.TempDir()
			floor := cur
			tc.bump(&floor)
			if err := trust.StoreSeen(stateHome, baseline.SeenKey, floor); err != nil {
				t.Fatal(err)
			}
			_, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(), StateHome: stateHome})
			if err == nil {
				t.Fatalf("expected the %s to be refused as a rollback (stored floor above the served serial)", tc.doc)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
			assertFloorRefusal(t, err, trust.SeenPath(stateHome, baseline.SeenKey))
		})
	}
}

func TestPullRefusesStrippedDocumentAfterSeen(t *testing.T) {
	for _, tc := range []struct {
		doc   string
		files []string
		want  string
	}{
		{"revocation list", []string{"revocations.json", "revocations.json.minisig"},
			"revocation list absent but upstream previously published serial 3 (rollback)"},
		{"trust bundle", []string{"trust-bundle.json", "trust-bundle.json.minisig"},
			"trust bundle absent but upstream previously published serial 1 (rollback)"},
	} {
		t.Run(tc.doc, func(t *testing.T) {
			outDir, trustRoot := buildUpstreamWithAllDocs(t)
			stateHome := t.TempDir()
			first, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(), StateHome: stateHome})
			if err != nil {
				t.Fatalf("first pull: %v", err)
			}
			if err := trust.StoreSeen(stateHome, first.SeenKey, first.Seen); err != nil {
				t.Fatal(err)
			}
			for _, f := range tc.files {
				if err := os.Remove(filepath.Join(outDir, f)); err != nil {
					t.Fatal(err)
				}
			}
			_, err = Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(), StateHome: stateHome})
			if err == nil {
				t.Fatalf("expected refusal: the upstream stopped serving a %s it had published", tc.doc)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
			assertFloorRefusal(t, err, trust.SeenPath(stateHome, first.SeenKey))
		})
	}
}

// Absence is only a strip once a serial above zero has been seen: an upstream
// that has never published a revocation list stays pullable, on the first pull
// and on every later one.
func TestPullAllowsRevocationListNeverSeen(t *testing.T) {
	outDir, trustRoot, _ := buildLocalRepoWithBundle(t) // publishes no revocations.json
	stateHome := t.TempDir()
	first, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(), StateHome: stateHome})
	if err != nil {
		t.Fatalf("first pull with no revocation list must succeed: %v", err)
	}
	if first.Seen.RevocationSerial != 0 {
		t.Fatalf("RevocationSerial = %d with no list published, want 0", first.Seen.RevocationSerial)
	}
	if err := trust.StoreSeen(stateHome, first.SeenKey, first.Seen); err != nil {
		t.Fatal(err)
	}
	if _, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(), StateHome: stateHome}); err != nil {
		t.Fatalf("later pull of an upstream that never published a revocation list must succeed: %v", err)
	}
}

func TestPullFailsClosedOnCorruptState(t *testing.T) {
	outDir, trustRoot := buildUpstreamWithAllDocs(t)
	stateHome := t.TempDir()
	first, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(), StateHome: stateHome})
	if err != nil {
		t.Fatalf("first pull: %v", err)
	}
	statePath := filepath.Join(stateHome, "trust", first.SeenKey+".json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	const garbage = "{not json"
	if err := os.WriteFile(statePath, []byte(garbage), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(), StateHome: stateHome})
	if err == nil {
		t.Fatal("a corrupt state file must fail closed, never reset the floors to zero")
	}
	if !strings.Contains(err.Error(), "parse trust state") {
		t.Fatalf("error = %v, want it to name the unparseable trust state", err)
	}
	if !strings.Contains(err.Error(), statePath) {
		t.Fatalf("error = %v, want it to name the record path %s", err, statePath)
	}
	assertFloorRefusal(t, err, statePath)
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != garbage {
		t.Fatalf("corrupt state file was rewritten to %q; it must be left for the operator", raw)
	}
}

func TestPullRequiresStateHome(t *testing.T) {
	outDir, trustRoot := buildLocalRepo(t)
	_, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir()})
	if err == nil {
		t.Fatal("a pull with no state directory must be refused, not run without anti-rollback floors")
	}
	if !strings.Contains(err.Error(), "anti-rollback") {
		t.Fatalf("error = %v, want it to name the missing anti-rollback state", err)
	}
}

func TestPullRejectsUnsafeSourceName(t *testing.T) {
	outDir, trustRoot := buildLocalRepo(t)
	for _, name := range []string{"", "../escape", "a/b", "up.stream"} {
		t.Run(name, func(t *testing.T) {
			_, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: name, StageDir: t.TempDir(), StateHome: t.TempDir()})
			if err == nil {
				t.Fatalf("source name %q keys a state file and must be refused", name)
			}
			if !strings.Contains(err.Error(), "not a valid slug") {
				t.Fatalf("error = %v, want the slug refusal", err)
			}
		})
	}
}

func TestStoreFloorsTakesPerDocumentMaximum(t *testing.T) {
	stateHome := t.TempDir()
	if err := StoreFloors(stateHome, []*PullResult{
		{SeenKey: "up.aaaaaaaaaaaaaaaa", Seen: trust.Seen{TrustSerial: 5, IndexSerial: 2, RevocationSerial: 7}},
		{SeenKey: "other.bbbbbbbbbbbbbbbb", Seen: trust.Seen{TrustSerial: 1, IndexSerial: 1}},
		{SeenKey: "up.aaaaaaaaaaaaaaaa", Seen: trust.Seen{TrustSerial: 4, IndexSerial: 3, BundleSerial: 1, RevocationSerial: 6}},
	}); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]trust.Seen{
		"up.aaaaaaaaaaaaaaaa":    {TrustSerial: 5, IndexSerial: 3, BundleSerial: 1, RevocationSerial: 7},
		"other.bbbbbbbbbbbbbbbb": {TrustSerial: 1, IndexSerial: 1},
	} {
		got, err := trust.LoadSeen(stateHome, key)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s floors = %+v, want %+v", key, got, want)
		}
	}
}

// A concurrent writer (or an earlier, longer run) may have stored a higher
// floor after this run's Pull loaded its baseline. Storing must never lower it.
func TestStoreFloorsNeverLowersAFloorStoredSincePull(t *testing.T) {
	outDir, trustRoot := buildUpstreamWithAllDocs(t)
	stateHome := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(), StateHome: stateHome})
	if err != nil {
		t.Fatal(err)
	}
	higher := res.Seen
	higher.TrustSerial += 10
	higher.RevocationSerial += 10
	if err := trust.StoreSeen(stateHome, res.SeenKey, higher); err != nil {
		t.Fatal(err)
	}
	if err := StoreFloors(stateHome, []*PullResult{res}); err != nil {
		t.Fatal(err)
	}
	got, err := trust.LoadSeen(stateHome, res.SeenKey)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, higher) {
		t.Fatalf("floors after StoreFloors = %+v, want the higher stored %+v kept", got, higher)
	}
}

func TestStoreFloorsFailsClosedOnCorruptRecord(t *testing.T) {
	stateHome := t.TempDir()
	path := filepath.Join(stateHome, "trust", "up.aaaaaaaaaaaaaaaa.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := StoreFloors(stateHome, []*PullResult{{SeenKey: "up.aaaaaaaaaaaaaaaa", Seen: trust.Seen{TrustSerial: 1}}})
	if err == nil || !strings.Contains(err.Error(), "parse trust state") {
		t.Fatalf("error = %v, want the corrupt record refused rather than overwritten", err)
	}
}

// assertFloorRefusal checks that err is Pull's UpstreamError for upstream
// "upstream", names it in its text, and points at the anti-rollback record.
func assertFloorRefusal(t *testing.T, err error, record string) {
	t.Helper()
	var ue *UpstreamError
	if !errors.As(err, &ue) {
		t.Fatalf("error = %T %v, want an *UpstreamError", err, err)
	}
	if !strings.HasPrefix(err.Error(), `upstream "upstream" (`) {
		t.Fatalf("error = %q, want it to start by naming the upstream", err)
	}
	if ue.FloorRecord != record {
		t.Fatalf("FloorRecord = %q, want %q", ue.FloorRecord, record)
	}
}

// Every Pull error names the upstream, with any credentials in the URL it
// adds redacted. (The wrapped transport error is source.FetchError's own
// text.) Only a refusal that comes from the anti-rollback record points at
// that record.
func TestPullErrorsNameTheUpstreamWithARedactedURL(t *testing.T) {
	_, trustRoot := buildLocalRepo(t)
	_, err := Pull(context.Background(), PullOptions{
		URL: "https://mirror-user:hunter2@127.0.0.1:1/repo", TrustRoot: trustRoot,
		SourceName: "upstream", StageDir: t.TempDir(), StateHome: t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected the fetch from a closed port to fail")
	}
	var ue *UpstreamError
	if !errors.As(err, &ue) {
		t.Fatalf("error = %T %v, want an *UpstreamError", err, err)
	}
	if !strings.HasPrefix(err.Error(), `upstream "upstream" (https://xxxxx@127.0.0.1:1/repo): `) {
		t.Fatalf("error = %q, want the upstream name and redacted URL first", err)
	}
	if strings.Contains(ue.URL, "hunter2") {
		t.Fatalf("UpstreamError.URL leaks the password: %q", ue.URL)
	}
	if ue.FloorRecord != "" {
		t.Fatalf("FloorRecord = %q for a fetch failure, want empty", ue.FloorRecord)
	}
}
