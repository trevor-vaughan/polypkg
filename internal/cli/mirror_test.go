package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func exportTestBundle(t *testing.T) (bundle, trustRoot string) {
	t.Helper()
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")
	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}
	writeHelloPkgSource(t, repoDir)
	mraw, err := os.ReadFile(mPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mPath, []byte(injectHelloPackage(t, repoDir, keyDir, mraw)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runRepo(t, env, "repo", "build", "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("build: %v", err)
	}
	bundle = filepath.Join(t.TempDir(), "bundle.tar")
	if _, err := runRepo(t, env, "repo", "export-bundle", "--manifest", mPath, "--key-dir", keyDir, "-o", bundle); err != nil {
		t.Fatalf("export: %v", err)
	}
	return bundle, filepath.Join(repoDir, "public", "trust_root.pub")
}

func TestMirrorVerifyAcceptsGoodBundle(t *testing.T) {
	bundle, root := exportTestBundle(t)
	out, err := runRepo(t, nil, "mirror", "verify", bundle, "--trust-root", root)
	if err != nil {
		t.Fatalf("mirror verify: %v (out=%s)", err, out)
	}
	if !strings.Contains(out, "OK") {
		t.Fatalf("expected OK in output, got %q", out)
	}
}

func TestMirrorVerifyRejectsMissingBundle(t *testing.T) {
	if _, err := runRepo(t, nil, "mirror", "verify", filepath.Join(t.TempDir(), "nope.tar")); err == nil {
		t.Fatal("expected error verifying a nonexistent bundle")
	}
}

func TestMirrorPullRequiresSourceOrSourcesFile(t *testing.T) {
	_, err := runRepo(t, nil, "mirror", "pull",
		"--repo-source", "local", "--output-dir", t.TempDir(),
		"--key", filepath.Join(t.TempDir(), "k.key"))
	if err == nil || !strings.Contains(err.Error(), "--source-url or --sources-file") {
		t.Fatalf("want missing-source error, got %v", err)
	}
}

func TestMirrorPullRejectsSourceAndSourcesFileTogether(t *testing.T) {
	_, err := runRepo(t, nil, "mirror", "pull",
		"--source-url", "file:///x", "--trust-root", "r.pub",
		"--sources-file", "s.yaml",
		"--repo-source", "local", "--output-dir", t.TempDir(),
		"--key", filepath.Join(t.TempDir(), "k.key"))
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want mutual-exclusion error, got %v", err)
	}
}

func TestMirrorPullSingleSourceRequiresTrustRoot(t *testing.T) {
	_, err := runRepo(t, nil, "mirror", "pull",
		"--source-url", "file:///x",
		"--repo-source", "local", "--output-dir", t.TempDir(),
		"--key", filepath.Join(t.TempDir(), "k.key"))
	if err == nil || !strings.Contains(err.Error(), "--trust-root is required") {
		t.Fatalf("want trust-root-required error, got %v", err)
	}
}

func TestMirrorPullSourcesFileRejectsSingleSourceFlags(t *testing.T) {
	_, err := runRepo(t, nil, "mirror", "pull",
		"--sources-file", "s.yaml", "--package", "foo",
		"--repo-source", "local", "--output-dir", t.TempDir(),
		"--key", filepath.Join(t.TempDir(), "k.key"))
	if err == nil || !strings.Contains(err.Error(), "cannot be combined with --sources-file") {
		t.Fatalf("want single-source-flag rejection, got %v", err)
	}
}

func TestMirrorPullSurfacesSourcesFileParseError(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("- url: https://a.example/repo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := runRepo(t, nil, "mirror", "pull",
		"--sources-file", bad,
		"--repo-source", "local", "--output-dir", t.TempDir(),
		"--key", filepath.Join(t.TempDir(), "k.key"))
	if err == nil || !strings.Contains(err.Error(), "trust_root is required") {
		t.Fatalf("want surfaced parse error naming the missing field, got %v", err)
	}
}

// buildUpstreamRepo builds a signed upstream repo (package "hello") and returns
// its served output dir + trust root, reusing the mirror_test fixture helpers.
func buildUpstreamRepo(t *testing.T) (outDir, trustRoot string) {
	t.Helper()
	repoDir := filepath.Join(t.TempDir(), "up")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")
	// injectHelloPackage rewrites the manifest with source "example", so the
	// built trust document is bound to that name; init with it to stay honest.
	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}
	writeHelloPkgSource(t, repoDir)
	mraw, err := os.ReadFile(mPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mPath, []byte(injectHelloPackage(t, repoDir, keyDir, mraw)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runRepo(t, env, "repo", "build", "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("build: %v", err)
	}
	return filepath.Join(repoDir, "public"), filepath.Join(repoDir, "public", "trust_root.pub")
}

// makeLocalKey generates an encrypted local signing key (password "pw") and
// returns (keyPath, keyDir).
func makeLocalKey(t *testing.T) (keyPath, keyDir string) {
	t.Helper()
	keyDir = t.TempDir()
	kp, err := repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(keyDir, "local.key")
	if err := repo.SaveKey(keyPath, kp, "pw", repo.KDFScrypt); err != nil {
		t.Fatal(err)
	}
	return keyPath, keyDir
}

func TestMirrorPullSingleSourceProducesVerifiableBundle(t *testing.T) {
	upstream, upTrust := buildUpstreamRepo(t)
	keyPath, keyDir := makeLocalKey(t)
	outputDir := filepath.Join(t.TempDir(), "local-repo")
	bundle := filepath.Join(t.TempDir(), "mirror.tar")
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}

	out, err := runRepo(t, env, "mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "example",
		"--repo-source", "local", "--output-dir", outputDir,
		"--key", keyPath, "--key-dir", keyDir,
		"-o", bundle)
	if err != nil {
		t.Fatalf("mirror pull: %v (out=%s)", err, out)
	}

	// The local repo was published and the bundle verifies against the LOCAL trust root.
	localTrust := filepath.Join(outputDir, "trust_root.pub")
	if _, err := runRepo(t, nil, "mirror", "verify", bundle, "--trust-root", localTrust); err != nil {
		t.Fatalf("mirror verify on pulled bundle: %v", err)
	}
	// Carried provenance survived: the re-published index references hello.
	idx, err := os.ReadFile(filepath.Join(outputDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(idx), "hello") {
		t.Fatalf("re-published index missing hello:\n%s", idx)
	}
}

// --key-dir names an operator-local build cache (a scratch content-hash cache,
// NOT the signing key — that loads from the manifest's absolute key.path), so
// mirror pull must create it when absent rather than fail on a missing dir.
func TestMirrorPullCreatesMissingKeyDir(t *testing.T) {
	upstream, upTrust := buildUpstreamRepo(t)
	keyPath, _ := makeLocalKey(t)
	missingCacheDir := filepath.Join(t.TempDir(), "cache-does-not-exist")
	outputDir := filepath.Join(t.TempDir(), "local-repo")
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}

	out, err := runRepo(t, env, "mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "example",
		"--repo-source", "local", "--output-dir", outputDir,
		"--key", keyPath, "--key-dir", missingCacheDir)
	if err != nil {
		t.Fatalf("mirror pull: %v (out=%s)", err, out)
	}
	if info, statErr := os.Stat(missingCacheDir); statErr != nil || !info.IsDir() {
		t.Fatalf("expected --key-dir to be created as a directory, stat err = %v", statErr)
	}
}

func TestMirrorPullFreshDropsUpstreamProvenance(t *testing.T) {
	upstream, upTrust := buildUpstreamRepo(t)
	keyPath, keyDir := makeLocalKey(t)
	outputDir := filepath.Join(t.TempDir(), "fresh-repo")
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}

	out, err := runRepo(t, env, "mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "example",
		"--repo-source", "local", "--output-dir", outputDir,
		"--key", keyPath, "--key-dir", keyDir, "--fresh")
	if err != nil {
		t.Fatalf("mirror pull --fresh: %v (out=%s)", err, out)
	}

	// No upstream attestations carried: the re-published index has no re-bound carried refs.
	idx, err := os.ReadFile(filepath.Join(outputDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(idx), "carried-opaque") {
		t.Fatalf("--fresh re-published index still carries upstream attestations:\n%s", idx)
	}
}

// buildUpstreamRepoWithBundle builds a signed upstream repo (package "hello")
// that ALSO publishes a repo-key-signed trust-bundle.json, so Pull stages it and
// a non-fresh re-publish carries it forward — giving --fresh a real bundle to strip.
func buildUpstreamRepoWithBundle(t *testing.T) (outDir, trustRoot string) {
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
		t.Fatalf("build bundle fixture: %v", err)
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
	return outDir, trustRoot
}

func TestMirrorPullFreshDropsTrustBundle(t *testing.T) {
	upstream, upTrust := buildUpstreamRepoWithBundle(t)
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}

	// Non-fresh carries the upstream trust bundle forward (proves non-vacuity).
	keyA, keyDirA := makeLocalKey(t)
	carried := filepath.Join(t.TempDir(), "carried")
	if _, err := runRepo(t, env, "mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "upstream",
		"--repo-source", "local", "--output-dir", carried,
		"--key", keyA, "--key-dir", keyDirA); err != nil {
		t.Fatalf("non-fresh pull: %v", err)
	}
	if _, err := os.Stat(filepath.Join(carried, "trust-bundle.json")); err != nil {
		t.Fatalf("non-fresh pull did not carry the trust bundle forward (test would be vacuous): %v", err)
	}

	// --fresh drops it.
	keyB, keyDirB := makeLocalKey(t)
	fresh := filepath.Join(t.TempDir(), "fresh")
	if _, err := runRepo(t, env, "mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "upstream",
		"--repo-source", "local", "--output-dir", fresh,
		"--key", keyB, "--key-dir", keyDirB, "--fresh"); err != nil {
		t.Fatalf("fresh pull: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fresh, "trust-bundle.json")); !os.IsNotExist(err) {
		t.Fatalf("--fresh emitted a trust bundle (upstream builder keys leaked); stat err = %v", err)
	}
}

// Leak 2 guard: --fresh must refuse a populated output dir.
func TestMirrorPullFreshRejectsNonEmptyOutput(t *testing.T) {
	upstream, upTrust := buildUpstreamRepo(t)
	keyPath, keyDir := makeLocalKey(t)
	outputDir := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "trust-bundle.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	_, err := runRepo(t, env, "mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "example",
		"--repo-source", "local", "--output-dir", outputDir,
		"--key", keyPath, "--key-dir", keyDir, "--fresh")
	if err == nil || !strings.Contains(err.Error(), "empty --output-dir") {
		t.Fatalf("want non-empty-output rejection, got %v", err)
	}
}

// Leak 1 guard: --fresh must NOT re-surface attestations from a build cache a
// prior non-fresh run populated (shared --key-dir cache, distinct clean outputs).
func TestMirrorPullFreshIgnoresPollutedBuildCache(t *testing.T) {
	upstream, upTrust := buildUpstreamRepo(t)
	keyPath, keyDir := makeLocalKey(t) // shared cache lives in keyDir
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}

	// Non-fresh first: populates the build cache in keyDir with the upstream attestation refs.
	nonFresh := filepath.Join(t.TempDir(), "nonfresh")
	if _, err := runRepo(t, env, "mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "example",
		"--repo-source", "local", "--output-dir", nonFresh,
		"--key", keyPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("non-fresh pull: %v", err)
	}
	if idx, _ := os.ReadFile(filepath.Join(nonFresh, "index.json")); !strings.Contains(string(idx), "carried-opaque") {
		t.Fatal("fixture invalid: non-fresh index should carry an attestation (test would be vacuous)")
	}

	// --fresh into a CLEAN output dir but reusing the SAME polluted --key-dir cache.
	fresh := filepath.Join(t.TempDir(), "fresh")
	if _, err := runRepo(t, env, "mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "example",
		"--repo-source", "local", "--output-dir", fresh,
		"--key", keyPath, "--key-dir", keyDir, "--fresh"); err != nil {
		t.Fatalf("fresh pull: %v", err)
	}
	idx, err := os.ReadFile(filepath.Join(fresh, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(idx), "carried-opaque") {
		t.Fatalf("--fresh re-surfaced a cached upstream attestation:\n%s", idx)
	}
}

// buildUpstreamRepoNamed builds a signed upstream repo via the repo APIs whose
// single package is pkgName and whose trust-doc source is sourceName (so a
// --sources-file entry can pin a matching source_name). No trust bundle / carried
// attestations — the multi-source fold test only needs both packages to land.
func buildUpstreamRepoNamed(t *testing.T, pkgName, sourceName string) (outDir, trustRoot string) {
	t.Helper()
	root := t.TempDir()
	keyDir := t.TempDir()
	pkgDir := filepath.Join(root, "pkgs", pkgName)
	if err := os.MkdirAll(filepath.Join(pkgDir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "polypkg.yaml"),
		[]byte("schema: polypkg.package/v1\nname: "+pkgName+"\nversion: 1.0.0\nactions: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "content", "bin", pkgName), []byte("#!/bin/sh\necho "+pkgName+"\n"), 0o755); err != nil {
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
	manifest := "schema: polypkg.repo/v1\nsource: " + sourceName + "\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  " + pkgName + ":\n    source: ./pkgs/" + pkgName + "\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(repo.BuildOptions{}); err != nil {
		t.Fatalf("build %s fixture: %v", pkgName, err)
	}
	return filepath.Join(root, "public"), filepath.Join(root, "public", "trust_root.pub")
}

// writeSourcesYAML writes a --sources-file from {url, trust_root, source_name} triples.
func writeSourcesYAML(t *testing.T, entries ...[3]string) string {
	t.Helper()
	var sb strings.Builder
	for _, e := range entries {
		sb.WriteString("- url: " + e[0] + "\n  trust_root: " + e[1] + "\n  source_name: " + e[2] + "\n")
	}
	p := filepath.Join(t.TempDir(), "sources.yaml")
	if err := os.WriteFile(p, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMirrorPullMultiSourceFoldsAllPackages(t *testing.T) {
	upA, trustA := buildUpstreamRepoNamed(t, "alpha", "upstream-alpha")
	upB, trustB := buildUpstreamRepoNamed(t, "beta", "upstream-beta")
	sources := writeSourcesYAML(t, [3]string{upA, trustA, "upstream-alpha"}, [3]string{upB, trustB, "upstream-beta"})
	keyPath, keyDir := makeLocalKey(t)
	outputDir := filepath.Join(t.TempDir(), "multi-repo")
	bundle := filepath.Join(t.TempDir(), "multi.tar")
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	if _, err := runRepo(t, env, "mirror", "pull",
		"--sources-file", sources,
		"--repo-source", "local", "--output-dir", outputDir,
		"--key", keyPath, "--key-dir", keyDir, "-o", bundle); err != nil {
		t.Fatalf("mirror pull multi: %v", err)
	}
	idx, err := os.ReadFile(filepath.Join(outputDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "beta"} {
		if !strings.Contains(string(idx), name) {
			t.Fatalf("multi-source index missing %q:\n%s", name, idx)
		}
	}
	if _, err := runRepo(t, nil, "mirror", "verify", bundle, "--trust-root", filepath.Join(outputDir, "trust_root.pub")); err != nil {
		t.Fatalf("verify multi bundle: %v", err)
	}
}

func TestMirrorPullMultiSourceRejectsDuplicatePackageName(t *testing.T) {
	upA, trustA := buildUpstreamRepoNamed(t, "dup", "upstream-a")
	upB, trustB := buildUpstreamRepoNamed(t, "dup", "upstream-b")
	sources := writeSourcesYAML(t, [3]string{upA, trustA, "upstream-a"}, [3]string{upB, trustB, "upstream-b"})
	keyPath, keyDir := makeLocalKey(t)
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	_, err := runRepo(t, env, "mirror", "pull",
		"--sources-file", sources,
		"--repo-source", "local", "--output-dir", filepath.Join(t.TempDir(), "r"),
		"--key", keyPath, "--key-dir", keyDir)
	if err == nil || !strings.Contains(err.Error(), "more than one source") {
		t.Fatalf("want cross-source duplicate-name failure, got %v", err)
	}
}
