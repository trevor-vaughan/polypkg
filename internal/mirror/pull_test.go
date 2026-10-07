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
	"time"

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
		if _, err := stagedPkgDir(root, tc.name, tc.version, ""); err == nil {
			t.Fatalf("expected rejection for name=%q version=%q", tc.name, tc.version)
		}
	}
	dir, err := stagedPkgDir(root, "hello", "1.0.0", "")
	if err != nil || dir != filepath.Join(root, "hello", "1.0.0", "any") {
		t.Fatalf("normal pkg: dir=%q err=%v", dir, err)
	}
}

func TestStagedPkgDirRejectsUnsafeName(t *testing.T) {
	root := t.TempDir()
	for _, bad := range []string{"hello\noutput: /tmp/x", "a:b", "foo bar", "eviL!", "na/me"} {
		if _, err := stagedPkgDir(root, bad, "1.0.0", ""); err == nil {
			t.Errorf("stagedPkgDir accepted unsafe name %q", bad)
		}
	}
	// A legitimate name still works.
	if _, err := stagedPkgDir(root, "hello_world-1", "1.0.0", ""); err != nil {
		t.Errorf("stagedPkgDir rejected a valid name: %v", err)
	}
	// An unsafe version is rejected.
	if _, err := stagedPkgDir(root, "hello", "1.0.0\nx: y", ""); err == nil {
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
	if want := `refusing to pull "hello" "1.0.0" (any)`; !strings.Contains(err.Error(), want) {
		t.Fatalf("error should name the refused build as %q, got: %v", want, err)
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
// is a valid input to `repo build`'s prebuilt ingest: pull →
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

	// Re-publish locally: fresh key + output, generate manifest, build
	// (prebuilt ingest).
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
	a, err := stagedPkgDir(root, "a", "b-1.0.0", "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := stagedPkgDir(root, "a-b", "1.0.0", "")
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
	writeIndexJSON(t, out, `{"schema":"polypkg.index/v3","expires":"2030-01-01T00:00:00Z","packages":{"hello":[{"version":"1.0.0","content_hash":"blake3:aa","artifact":"pool/aa.tar.zst","revision":1}]}}`)
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
	writeIndexJSON(t, out, `{"schema":"polypkg.index/v3","expires":"2030-01-01T00:00:00Z","packages":{"hello":[{"version":"1.0.0","content_hash":"blake3:aa","artifact":"pool/aa.tar.zst","revision":1}]}}`)

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
	writeIndexJSON(t, out, `{"schema":"polypkg.index/v3","expires":"2030-01-01T00:00:00Z","packages":{"hello":[{"version":"1.0.0","content_hash":"blake3:aa","artifact":"pool/aa.tar.zst","revision":1},{"version":"1.1.0","content_hash":"blake3:bb","artifact":"pool/bb.tar.zst","revision":1}]}}`)
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

// TestStagedPkgDirUsesSchemaNameRule pins the mirror's name check to the
// shared schema rule, so the staging boundary cannot drift from the slug the
// index schema and the catalog enforce.
func TestStagedPkgDirUsesSchemaNameRule(t *testing.T) {
	_, err := stagedPkgDir(t.TempDir(), "py3.11", "1.0.0", "")
	if err == nil {
		t.Fatal("stagedPkgDir accepted a name outside the package-name slug")
	}
	if !strings.Contains(err.Error(), schema.PackageNamePattern) {
		t.Errorf("error %q does not cite schema.PackageNamePattern %s", err, schema.PackageNamePattern)
	}
}

// TestStagedPkgDirSeparatesPlatforms proves that each platform build of one
// version, and the platform-agnostic build, gets its own staging dir. Before
// this, two platform builds of hello 1.0.0 staged into one dir and the second
// overwrote the first.
func TestStagedPkgDirSeparatesPlatforms(t *testing.T) {
	root := t.TempDir()
	cases := []struct{ platform, wantLeaf string }{
		{"linux/amd64", "linux-amd64"},
		{"darwin/arm64", "darwin-arm64"},
		{"linux/arm/v7", "linux-arm-v7"},
		{"", "any"},
	}
	seen := map[string]string{}
	for _, tc := range cases {
		dir, err := stagedPkgDir(root, "hello", "1.0.0", tc.platform)
		if err != nil {
			t.Fatalf("platform %q: %v", tc.platform, err)
		}
		if want := filepath.Join(root, "hello", "1.0.0", tc.wantLeaf); dir != want {
			t.Errorf("platform %q: dir = %q, want %q", tc.platform, dir, want)
		}
		if prev, dup := seen[dir]; dup {
			t.Fatalf("platforms %q and %q collide on staging dir %q", prev, tc.platform, dir)
		}
		seen[dir] = tc.platform
	}
}

// TestStagedPkgDirRejectsUnsafePlatform proves that the platform segment is
// held to the consumer grammar before it reaches the filesystem: no traversal,
// no separators, no case or shape the grammar cannot produce, and not the
// reserved "any" (which would alias the platform-agnostic dir).
func TestStagedPkgDirRejectsUnsafePlatform(t *testing.T) {
	root := t.TempDir()
	for _, bad := range []string{
		"any",
		"linux-amd64",
		"linux",
		"../../evil",
		"linux/../../evil",
		"linux/amd64/../..",
		`linux\amd64`,
		"Linux/amd64",
		"linux/amd64/v7/x",
		"linux//amd64",
		"/linux/amd64",
		"linux/amd64\nx: y",
	} {
		_, err := stagedPkgDir(root, "hello", "1.0.0", bad)
		if err == nil {
			t.Errorf("stagedPkgDir accepted unsafe platform %q", bad)
			continue
		}
		if want := fmt.Sprintf(`refusing package "hello" "1.0.0": unsafe platform %q`, bad); !strings.Contains(err.Error(), want) {
			t.Errorf("platform %q: error = %v, want it to contain %q", bad, err, want)
		}
	}
}

// twoPlatformIndex is hello published at 1.0.0 and 1.1.0, each for
// linux/amd64 and darwin/arm64. Entries are deliberately listed linux-first
// so the tests prove the platform ordering is imposed, not inherited.
func twoPlatformIndex() *schema.Index {
	return &schema.Index{Packages: map[string][]schema.IndexEntry{
		"hello": {
			{Version: "1.0.0", Platform: "linux/amd64", ContentHash: "blake3:a1"},
			{Version: "1.0.0", Platform: "darwin/arm64", ContentHash: "blake3:a2"},
			{Version: "1.1.0", Platform: "linux/amd64", ContentHash: "blake3:b1"},
			{Version: "1.1.0", Platform: "darwin/arm64", ContentHash: "blake3:b2"},
		},
	}}
}

// selectedHashes returns the content hashes of sels in order.
func selectedHashes(sels []pullSelection) []string {
	out := make([]string, len(sels))
	for i := range sels {
		out[i] = sels[i].entry.ContentHash
	}
	return out
}

// TestResolvePullSelectionLatestIsNewestPerPlatform is the headline case:
// "latest" is the newest version per (name, platform). When linux has 1.1.0
// and darwin only 1.0.0, both builds are mirrored, so a client on either host
// finds its own newest build. Neither build is reported as skipped.
func TestResolvePullSelectionLatestIsNewestPerPlatform(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"hello": {
			{Version: "1.1.0", Platform: "linux/amd64", ContentHash: "blake3:linux110"},
			{Version: "1.0.0", Platform: "darwin/arm64", ContentHash: "blake3:darwin100"},
		},
	}}
	for _, selectors := range [][]string{nil, {"hello"}} {
		got, notes, err := resolvePullSelection(idx, selectors, false)
		if err != nil {
			t.Fatalf("selectors %v: %v", selectors, err)
		}
		if want := []string{"blake3:darwin100", "blake3:linux110"}; !reflect.DeepEqual(selectedHashes(got), want) {
			t.Fatalf("selectors %v: selected %v, want %v (each platform's newest build)", selectors, selectedHashes(got), want)
		}
		if len(notes) != 0 {
			t.Fatalf("selectors %v: notes = %v, want none (each platform's newest build was mirrored)", selectors, notes)
		}
	}
}

// TestResolvePullSelectionLatestNotesPerPlatform proves that when both
// platforms published 1.0.0 and 1.1.0, "latest" mirrors 1.1.0 for each, and
// each platform reports its own superseded 1.0.0 once.
func TestResolvePullSelectionLatestNotesPerPlatform(t *testing.T) {
	for _, selectors := range [][]string{nil, {"hello"}} {
		got, notes, err := resolvePullSelection(twoPlatformIndex(), selectors, false)
		if err != nil {
			t.Fatalf("selectors %v: %v", selectors, err)
		}
		if want := []string{"blake3:b2", "blake3:b1"}; !reflect.DeepEqual(selectedHashes(got), want) {
			t.Fatalf("selectors %v: selected %v, want %v (1.1.0 darwin then linux)", selectors, selectedHashes(got), want)
		}
		want := []string{
			"hello (darwin/arm64): mirrored 1.1.0, did not mirror 1.0.0 (select it with --package hello@1.0.0)",
			"hello (linux/amd64): mirrored 1.1.0, did not mirror 1.0.0 (select it with --package hello@1.0.0)",
		}
		if !reflect.DeepEqual(notes, want) {
			t.Fatalf("selectors %v: notes = %q, want %q", selectors, notes, want)
		}
	}
}

// TestResolvePullSelectionSupersededOnOnePlatformOnly proves that a version
// published on two platforms but superseded on only one is mirrored where it
// is still newest (darwin) and reported as skipped only where it was
// superseded (linux).
func TestResolvePullSelectionSupersededOnOnePlatformOnly(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"hello": {
			{Version: "1.0.0", Platform: "linux/amd64", ContentHash: "blake3:linux100"},
			{Version: "1.1.0", Platform: "linux/amd64", ContentHash: "blake3:linux110"},
			{Version: "1.0.0", Platform: "darwin/arm64", ContentHash: "blake3:darwin100"},
		},
	}}
	got, notes, err := resolvePullSelection(idx, nil, false)
	if err != nil {
		t.Fatalf("resolvePullSelection: %v", err)
	}
	if want := []string{"blake3:darwin100", "blake3:linux110"}; !reflect.DeepEqual(selectedHashes(got), want) {
		t.Fatalf("selected %v, want %v", selectedHashes(got), want)
	}
	want := []string{"hello (linux/amd64): mirrored 1.1.0, did not mirror 1.0.0 (select it with --package hello@1.0.0)"}
	if !reflect.DeepEqual(notes, want) {
		t.Fatalf("notes = %q, want %q (darwin's newest 1.0.0 is not skipped)", notes, want)
	}
}

// TestResolvePullSelectionLatestAgnosticAlongsidePlatforms proves that
// platform-agnostic entries form their own "latest" group. This holds for an
// agnostic package next to a per-platform one, and for one package whose
// older version was agnostic and whose newer version is per-platform. The
// agnostic group's note keeps the unqualified wording.
func TestResolvePullSelectionLatestAgnosticAlongsidePlatforms(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"greet": {
			{Version: "1.0.0", ContentHash: "blake3:greet100"},
			{Version: "1.1.0", ContentHash: "blake3:greet110"},
		},
		"hello": {
			{Version: "1.0.0", Platform: "linux/amd64", ContentHash: "blake3:hello-linux"},
			{Version: "1.0.0", Platform: "darwin/arm64", ContentHash: "blake3:hello-darwin"},
		},
		"tool": {
			{Version: "1.0.0", ContentHash: "blake3:tool-any"},
			{Version: "2.0.0", Platform: "linux/amd64", ContentHash: "blake3:tool-linux"},
		},
	}}
	got, notes, err := resolvePullSelection(idx, nil, false)
	if err != nil {
		t.Fatalf("resolvePullSelection: %v", err)
	}
	// Names sorted; within a name the agnostic group ("") sorts first.
	want := []string{"blake3:greet110", "blake3:hello-darwin", "blake3:hello-linux", "blake3:tool-any", "blake3:tool-linux"}
	if !reflect.DeepEqual(selectedHashes(got), want) {
		t.Fatalf("selected %v, want %v", selectedHashes(got), want)
	}
	wantNotes := []string{"greet: mirrored 1.1.0, did not mirror 1.0.0 (select it with --package greet@1.0.0)"}
	if !reflect.DeepEqual(notes, wantNotes) {
		t.Fatalf("notes = %q, want %q", notes, wantNotes)
	}
}

// TestResolvePullSelectionPinnedVersionSelectsEveryPlatform proves that
// "name@version" selects every platform build of that version, not just the
// first matching entry.
func TestResolvePullSelectionPinnedVersionSelectsEveryPlatform(t *testing.T) {
	got, notes, err := resolvePullSelection(twoPlatformIndex(), []string{"hello@1.0.0"}, false)
	if err != nil {
		t.Fatalf("resolvePullSelection: %v", err)
	}
	if want := []string{"blake3:a2", "blake3:a1"}; !reflect.DeepEqual(selectedHashes(got), want) {
		t.Fatalf("selected %v, want %v (1.0.0 darwin then linux)", selectedHashes(got), want)
	}
	if len(notes) != 0 {
		t.Fatalf("notes = %v, want none (explicit pin)", notes)
	}
}

// TestResolvePullSelectionAllVersionsOrdersByVersionThenPlatform proves that
// --all-versions keeps a byte-stable order once versions repeat across
// platforms: newest version first, then platform.
func TestResolvePullSelectionAllVersionsOrdersByVersionThenPlatform(t *testing.T) {
	got, _, err := resolvePullSelection(twoPlatformIndex(), nil, true)
	if err != nil {
		t.Fatalf("resolvePullSelection: %v", err)
	}
	if want := []string{"blake3:b2", "blake3:b1", "blake3:a2", "blake3:a1"}; !reflect.DeepEqual(selectedHashes(got), want) {
		t.Fatalf("selected %v, want %v", selectedHashes(got), want)
	}
}

// TestResolvePullSelectionOneVersionManyPlatformsNoNote proves that one version
// published for several platforms is not "narrowing": nothing was left behind.
// Before this fix it produced a note naming an empty list of skipped versions.
func TestResolvePullSelectionOneVersionManyPlatformsNoNote(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"hello": {
			{Version: "1.0.0", Platform: "linux/amd64", ContentHash: "blake3:a1"},
			{Version: "1.0.0", Platform: "darwin/arm64", ContentHash: "blake3:a2"},
		},
	}}
	got, notes, err := resolvePullSelection(idx, nil, false)
	if err != nil {
		t.Fatalf("resolvePullSelection: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("selected %d builds, want 2: %+v", len(got), got)
	}
	if len(notes) != 0 {
		t.Fatalf("notes = %v, want none (the only version was mirrored for every platform)", notes)
	}
}

// TestResolvePullSelectionRefusesDuplicatePlatformBuild proves that an upstream
// index listing one (name, version, platform) twice is refused on every
// selection path, including one that does not select the malformed package.
// repo build never publishes such an index; per-platform "latest" would drop
// the duplicate silently, and a pin would stage both copies to one directory.
func TestResolvePullSelectionRefusesDuplicatePlatformBuild(t *testing.T) {
	for _, tc := range []struct {
		platform, wantInErr string
	}{
		{"linux/amd64", `upstream index lists "hello" "1.0.0" for platform "linux/amd64" more than once`},
		{"", `upstream index lists "hello" "1.0.0" for platform "any" more than once`},
	} {
		idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
			"hello": {
				{Version: "1.0.0", Platform: tc.platform, ContentHash: "blake3:a1"},
				{Version: "1.0.0", Platform: tc.platform, ContentHash: "blake3:a2"},
			},
			"greet": {{Version: "1.0.0", ContentHash: "blake3:g1"}},
		}}
		for _, sel := range []struct {
			selectors   []string
			allVersions bool
		}{
			{nil, false}, {nil, true}, {[]string{"hello"}, false}, {[]string{"hello"}, true},
			{[]string{"hello@1.0.0"}, false}, {[]string{"greet"}, false},
		} {
			_, _, err := resolvePullSelection(idx, sel.selectors, sel.allVersions)
			if err == nil {
				t.Fatalf("platform %q, selectors %v, all=%v: expected refusal of a duplicate build", tc.platform, sel.selectors, sel.allVersions)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("platform %q, selectors %v, all=%v: error = %v, want it to contain %q", tc.platform, sel.selectors, sel.allVersions, err, tc.wantInErr)
			}
		}
	}
}

// TestResolvePullSelectionRefusesCaseFoldCollisions proves that an upstream
// index whose names, or whose versions of one name, differ only in letter
// case is refused on every selection path, before anything is staged: the
// staging layout <name>/<version>/ would merge them on a case-insensitive
// filesystem.
func TestResolvePullSelectionRefusesCaseFoldCollisions(t *testing.T) {
	for _, tc := range []struct {
		packages  map[string][]schema.IndexEntry
		wantInErr string
	}{
		{
			map[string][]schema.IndexEntry{
				"hello": {{Version: "1.0.0", ContentHash: "blake3:h1"}},
				"Hello": {{Version: "1.0.0", ContentHash: "blake3:h2"}},
			},
			`upstream index: package names "Hello" and "hello" differ only in letter case`,
		},
		{
			map[string][]schema.IndexEntry{
				"hello": {
					{Version: "1.0.0-rc1", ContentHash: "blake3:h1"},
					{Version: "1.0.0-RC1", ContentHash: "blake3:h2"},
				},
			},
			`upstream index: package "hello" versions "1.0.0-rc1" and "1.0.0-RC1" differ only in letter case`,
		},
	} {
		idx := &schema.Index{Packages: tc.packages}
		for _, sel := range []struct {
			selectors   []string
			allVersions bool
		}{{nil, false}, {nil, true}, {[]string{"hello"}, false}, {[]string{"hello@1.0.0-rc1"}, false}} {
			_, _, err := resolvePullSelection(idx, sel.selectors, sel.allVersions)
			if err == nil || !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("selectors %v, all=%v: error = %v, want it to contain %q", sel.selectors, sel.allVersions, err, tc.wantInErr)
			}
		}
	}
}

// buildLocalRepoMultiPlatform builds an upstream publishing hello 1.0.0 for
// linux/amd64 and darwin/arm64, plus a platform-agnostic greet 1.0.0, and
// returns its public dir and trust root. Mirrors buildLocalRepoTwoVersions.
func buildLocalRepoMultiPlatform(t *testing.T) (outDir, trustRoot string) {
	t.Helper()
	root := t.TempDir()
	keyDir := t.TempDir()

	for _, s := range []struct{ dir, name, platformLine string }{
		{"hello-linux", "hello", "platform: linux/amd64\n"},
		{"hello-darwin", "hello", "platform: darwin/arm64\n"},
		{"greet", "greet", ""},
	} {
		dir := filepath.Join(root, "pkgs", s.dir)
		if err := os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		pm := "schema: polypkg.package/v1\nname: " + s.name + "\nversion: 1.0.0\n" + s.platformLine + "actions: []\n"
		if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(pm), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "content", "bin", s.name),
			[]byte("#!/bin/sh\necho "+s.dir+"\n"), 0o755); err != nil {
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
		"packages:\n" +
		"  hello:\n    - source: ./pkgs/hello-linux\n    - source: ./pkgs/hello-darwin\n" +
		"  greet:\n    - source: ./pkgs/greet\n"
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

// TestPullStagesEachPlatformBuildSeparately is the end-to-end proof against a
// real signed upstream: both platform builds of hello 1.0.0 and the agnostic
// greet are fetched, verified, and staged at distinct paths, each byte-for-byte
// the artifact its index entry names, with its attestations beside it.
func TestPullStagesEachPlatformBuildSeparately(t *testing.T) {
	outDir, trustRoot := buildLocalRepoMultiPlatform(t)
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	stagingRoot := filepath.Join(stage, "staging")
	want := map[string]bool{
		filepath.Join(stagingRoot, "hello", "1.0.0", "darwin-arm64", "hello.tar.zst"): true,
		filepath.Join(stagingRoot, "hello", "1.0.0", "linux-amd64", "hello.tar.zst"):  true,
		filepath.Join(stagingRoot, "greet", "1.0.0", "any", "greet.tar.zst"):          true,
	}
	if len(res.Packages) != len(want) {
		t.Fatalf("pulled %d builds, want %d: %+v", len(res.Packages), len(want), res.Packages)
	}
	hashes := map[string]bool{}
	for _, p := range res.Packages {
		if !want[p.ArtifactPath] {
			t.Errorf("unexpected staged artifact %q", p.ArtifactPath)
		}
		got, err := os.ReadFile(p.ArtifactPath)
		if err != nil {
			t.Fatalf("staged artifact %q: %v", p.ArtifactPath, err)
		}
		if contentHash(got) != p.ContentHash {
			t.Errorf("staged %q hashes to %s, index says %s (overwritten by another build?)", p.ArtifactPath, contentHash(got), p.ContentHash)
		}
		if filepath.Dir(p.AttDir) != filepath.Dir(p.ArtifactPath) {
			t.Errorf("attestations %q are not beside their artifact %q", p.AttDir, p.ArtifactPath)
		}
		hashes[p.ContentHash] = true
	}
	if len(hashes) != len(want) {
		t.Fatalf("pulled builds share content hashes %v; want %d distinct builds", hashes, len(want))
	}
	if len(res.Narrowed) != 0 {
		t.Fatalf("Narrowed = %v, want none (one version, every platform mirrored)", res.Narrowed)
	}
}

// TestWriteManagementManifestEmitsOnePrebuiltPerPlatformBuild proves that a
// published index listing two platform builds of one version emits two
// "- prebuilt:" items under one "hello:" key, each at its own pool blob.
func TestWriteManagementManifestEmitsOnePrebuiltPerPlatformBuild(t *testing.T) {
	out := filepath.Join(t.TempDir(), "mirror")
	writeIndexJSON(t, out, `{"schema":"polypkg.index/v3","expires":"2030-01-01T00:00:00Z","packages":{"hello":[`+
		`{"version":"1.0.0","platform":"darwin/arm64","content_hash":"blake3:aa","artifact":"pool/aa.tar.zst","revision":1},`+
		`{"version":"1.0.0","platform":"linux/amd64","content_hash":"blake3:bb","artifact":"pool/bb.tar.zst","revision":1}]}}`)

	if err := WriteManagementManifest(PrebuiltManifestParams{
		Source: "mymirror", Output: out, KeyPath: filepath.Join(t.TempDir(), "local.key"), KeyKDF: "scrypt",
	}); err != nil {
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
	pkg := m.Packages["hello"]
	if len(pkg) != 2 {
		t.Fatalf("want 2 prebuilt entries for hello (one per platform build), got %+v", pkg)
	}
	for i, want := range []string{filepath.Join(out, "pool", "aa.tar.zst"), filepath.Join(out, "pool", "bb.tar.zst")} {
		if pkg[i].Prebuilt == nil || pkg[i].Prebuilt.Artifact != want {
			t.Errorf("entry %d = %+v, want artifact %q", i, pkg[i].Prebuilt, want)
		}
	}
}

// TestPullMultiPlatformSurvivesMirrorRepublish follows two platform builds of
// one version, plus an agnostic package, through every mirror hop: the
// prebuilt manifest, repo build's ingest, and the management manifest
// regenerated from the published index. Every hop must keep both builds.
func TestPullMultiPlatformSurvivesMirrorRepublish(t *testing.T) {
	outDir, trustRoot := buildLocalRepoMultiPlatform(t)
	stage := t.TempDir()
	res, err := Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: stage, StateHome: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("pull: %v", err)
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

	// Hop 1: the prebuilt manifest carries both hello builds and greet.
	mRaw, err := os.ReadFile(mPath)
	if err != nil {
		t.Fatal(err)
	}
	built, perr := schema.ParseRepoManifest(bytesReader(mRaw))
	if perr != nil {
		t.Fatalf("prebuilt manifest fails schema parse (duplicate YAML key?): %v\n%s", perr, mRaw)
	}
	hello := built.Packages["hello"]
	if len(hello) != 2 || hello[0].Prebuilt == nil || hello[1].Prebuilt == nil {
		t.Fatalf("prebuilt manifest carries %+v for hello, want two prebuilt entries", hello)
	}
	if hello[0].Prebuilt.Artifact == hello[1].Prebuilt.Artifact {
		t.Fatalf("both hello builds point at one staged artifact %q", hello[0].Prebuilt.Artifact)
	}
	if g := built.Packages["greet"]; len(g) != 1 || g[0].Prebuilt == nil {
		t.Fatalf("prebuilt manifest carries %+v for greet, want one prebuilt entry", g)
	}

	// Hop 2: repo build re-publishes each build under its own platform.
	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("new builder on the pulled manifest: %v", err)
	}
	if _, err := b.Build(repo.BuildOptions{}); err != nil {
		t.Fatalf("repo build (ingest) on the pulled manifest failed: %v", err)
	}
	idxRaw, err := os.ReadFile(filepath.Join(localOut, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	idx, err := schema.ParseIndex(bytesReader(idxRaw))
	if err != nil {
		t.Fatalf("published index invalid: %v", err)
	}
	platforms := map[string]bool{}
	for _, e := range idx.Packages["hello"] {
		platforms[e.Platform] = true
	}
	if len(idx.Packages["hello"]) != 2 || !platforms["linux/amd64"] || !platforms["darwin/arm64"] {
		t.Fatalf("published hello entries = %+v, want one linux/amd64 and one darwin/arm64", idx.Packages["hello"])
	}
	if g := idx.Packages["greet"]; len(g) != 1 || g[0].Platform != "" {
		t.Fatalf("published greet entries = %+v, want one platform-agnostic entry", g)
	}

	// Hop 3: the management manifest regenerated from the published index
	// points each build at its own, existing pool blob.
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
	pk := mgmt.Packages["hello"]
	if len(pk) != 2 {
		t.Fatalf("management manifest carries %d prebuilt(s) for hello, want 2: %+v", len(pk), pk)
	}
	for i := range pk {
		if pk[i].Prebuilt == nil {
			t.Fatalf("hello entry %d is not prebuilt: %+v", i, pk[i])
		}
		if _, err := os.Stat(pk[i].Prebuilt.Artifact); err != nil {
			t.Fatalf("hello entry %d names a pool blob that does not exist: %v", i, err)
		}
	}
	if pk[0].Prebuilt.Artifact == pk[1].Prebuilt.Artifact {
		t.Fatalf("both hello builds point at one pool blob %q", pk[0].Prebuilt.Artifact)
	}
	if g := mgmt.Packages["greet"]; len(g) != 1 || g[0].Prebuilt == nil {
		t.Fatalf("management manifest carries %+v for greet, want one prebuilt entry", g)
	}
}

// TestPullErrorNamesPlatformBuild proves that a failure while staging one
// platform build names that build, quoted name and version plus platform, so
// an operator can tell which of several builds of one version failed.
func TestPullErrorNamesPlatformBuild(t *testing.T) {
	outDir, trustRoot := buildLocalRepoMultiPlatform(t)
	raw, err := os.ReadFile(filepath.Join(outDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	idx, err := schema.ParseIndex(bytesReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var art string
	for i := range idx.Packages["hello"] {
		if idx.Packages["hello"][i].Platform == "darwin/arm64" {
			art = idx.Packages["hello"][i].Artifact
		}
	}
	if art == "" {
		t.Fatal("fixture: no darwin/arm64 build of hello")
	}
	if err := os.Remove(filepath.Join(outDir, filepath.FromSlash(art))); err != nil {
		t.Fatal(err)
	}
	_, err = Pull(context.Background(), PullOptions{
		URL: outDir, TrustRoot: trustRoot, SourceName: "upstream", StageDir: t.TempDir(), StateHome: t.TempDir(),
	})
	if want := `fetch artifact "hello" "1.0.0" (darwin/arm64)`; err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want it to contain %q", err, want)
	}
}

// TestResolvePullSelectionRefusesSemverEqualSpellings proves that an
// upstream index listing two spellings of one semver version (build metadata,
// a "v" prefix, a missing patch) for one platform group is refused on every
// selection path, in either index order: per-platform "latest" could keep
// only one of them, and repo build would refuse to publish both.
func TestResolvePullSelectionRefusesSemverEqualSpellings(t *testing.T) {
	for _, pair := range [][2]string{{"1.0.0+a", "1.0.0+b"}, {"v1.0.0", "1.0.0"}, {"1.0", "1.0.0"}} {
		for _, plat := range []struct{ name, shown string }{{"", "any"}, {"linux/amd64", "linux/amd64"}} {
			for _, order := range [][2]string{{pair[0], pair[1]}, {pair[1], pair[0]}} {
				idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
					"hello": {
						{Version: order[0], Platform: plat.name, ContentHash: "blake3:" + order[0]},
						{Version: order[1], Platform: plat.name, ContentHash: "blake3:" + order[1]},
					},
				}}
				want := fmt.Sprintf("upstream index lists %q %q for platform %q more than once (also as %q)",
					"hello", order[1], plat.shown, order[0])
				for _, sel := range []struct {
					selectors   []string
					allVersions bool
				}{{nil, false}, {nil, true}, {[]string{"hello@" + order[0]}, false}} {
					_, _, err := resolvePullSelection(idx, sel.selectors, sel.allVersions)
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("order %v, platform %q, selectors %v: error = %v, want it to contain %q",
							order, plat.name, sel.selectors, err, want)
					}
				}
			}
		}
	}
}

// TestResolvePullSelectionKeepsSemverEqualSpellingsOnDistinctPlatforms
// proves the duplicate check is per platform group: "1.0" for one platform
// and "1.0.0" for another are two builds of one version, and both are
// selected.
func TestResolvePullSelectionKeepsSemverEqualSpellingsOnDistinctPlatforms(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"hello": {
			{Version: "1.0", Platform: "linux/amd64", ContentHash: "blake3:linux"},
			{Version: "1.0.0", Platform: "darwin/arm64", ContentHash: "blake3:darwin"},
		},
	}}
	got, _, err := resolvePullSelection(idx, nil, false)
	if err != nil {
		t.Fatalf("resolvePullSelection: %v", err)
	}
	if want := []string{"blake3:darwin", "blake3:linux"}; !reflect.DeepEqual(selectedHashes(got), want) {
		t.Fatalf("selected %v, want %v", selectedHashes(got), want)
	}
}

// TestResolvePullSelectionLatestIgnoresIndexOrder proves that "latest" within
// a platform group does not depend on where the index lists each version: an
// older version listed after a newer one does not displace it.
func TestResolvePullSelectionLatestIgnoresIndexOrder(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"hello": {
			{Version: "1.1.0", Platform: "linux/amd64", ContentHash: "blake3:linux110"},
			{Version: "1.0.0", Platform: "linux/amd64", ContentHash: "blake3:linux100"},
			{Version: "2.0.0", Platform: "darwin/arm64", ContentHash: "blake3:darwin200"},
			{Version: "1.9.0", Platform: "darwin/arm64", ContentHash: "blake3:darwin190"},
		},
	}}
	got, notes, err := resolvePullSelection(idx, nil, false)
	if err != nil {
		t.Fatalf("resolvePullSelection: %v", err)
	}
	if want := []string{"blake3:darwin200", "blake3:linux110"}; !reflect.DeepEqual(selectedHashes(got), want) {
		t.Fatalf("selected %v, want %v", selectedHashes(got), want)
	}
	want := []string{
		"hello (darwin/arm64): mirrored 2.0.0, did not mirror 1.9.0 (select it with --package hello@1.9.0)",
		"hello (linux/amd64): mirrored 1.1.0, did not mirror 1.0.0 (select it with --package hello@1.0.0)",
	}
	if !reflect.DeepEqual(notes, want) {
		t.Fatalf("notes = %q, want %q", notes, want)
	}
}

// TestResolvePullSelectionNoteOrdersSkippedBySemver proves that the narrowing
// note lists skipped versions in semver order, not text order (1.10.0 after
// 1.9.0), each in its published spelling.
func TestResolvePullSelectionNoteOrdersSkippedBySemver(t *testing.T) {
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{
		"hello": {
			{Version: "1.10.0", ContentHash: "blake3:1100"},
			{Version: "2.0.0", ContentHash: "blake3:200"},
			{Version: "1.2.0", ContentHash: "blake3:120"},
			{Version: "1.9.0+a", ContentHash: "blake3:190a"},
		},
	}}
	_, notes, err := resolvePullSelection(idx, nil, false)
	if err != nil {
		t.Fatalf("resolvePullSelection: %v", err)
	}
	want := []string{"hello: mirrored 2.0.0, did not mirror 1.2.0, 1.9.0+a, 1.10.0 (select each with --package hello@<version>)"}
	if !reflect.DeepEqual(notes, want) {
		t.Fatalf("notes = %q, want %q", notes, want)
	}
}

// TestRefuseDuplicateBuildsIsLinear pins that the duplicate check does not
// compare every pair of entries: 100 000 versions take well under a second,
// where a pairwise check takes minutes.
func TestRefuseDuplicateBuildsIsLinear(t *testing.T) {
	entries := make([]schema.IndexEntry, 0, 100_001)
	for i := range 100_000 {
		entries = append(entries, schema.IndexEntry{Version: fmt.Sprintf("1.%d.0", i), Platform: "linux/amd64"})
	}
	idx := &schema.Index{Packages: map[string][]schema.IndexEntry{"hello": entries}}
	start := time.Now()
	if err := refuseDuplicateBuilds(idx); err != nil {
		t.Fatalf("refuseDuplicateBuilds: %v", err)
	}
	idx.Packages["hello"] = append(entries, schema.IndexEntry{Version: "1.0", Platform: "linux/amd64"})
	want := `upstream index lists "hello" "1.0" for platform "linux/amd64" more than once (also as "1.0.0")`
	if err := refuseDuplicateBuilds(idx); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("refuseDuplicateBuilds = %v, want it to contain %q", err, want)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("checking 100 000 versions took %v", elapsed)
	}
}
