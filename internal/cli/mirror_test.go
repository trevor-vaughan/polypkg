package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

func exportTestBundle(t *testing.T) (bundle, trustRoot string) {
	t.Helper()
	mPath, keyDir := buildHelloRepo(t)
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	bundle = filepath.Join(t.TempDir(), "bundle.tar")
	if _, err := runRepo(t, env, "repo", "export-bundle", "--manifest", mPath, "--key-dir", keyDir, "-o", bundle); err != nil {
		t.Fatalf("export: %v", err)
	}
	return bundle, filepath.Join(filepath.Dir(mPath), "public", "trust_root.pub")
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
	sandboxUserEnv(t)
	missing := filepath.Join(t.TempDir(), "nope.tar")
	_, err := runRepo(t, nil, "mirror", "verify", missing)
	var ce *CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("want a *CLIError, got %T: %v", err, err)
	}
	if want := "bundle " + missing + " does not exist"; ce.Msg != want {
		t.Fatalf("Msg = %q, want %q", ce.Msg, want)
	}
	if !strings.Contains(ce.Hint, "export-bundle") {
		t.Fatalf("Hint = %q", ce.Hint)
	}
}

// A file that is not a tar archive, or a bundle cut short in transit, is
// named as not a bundle rather than with the tar reader's own error.
func TestMirrorVerifyRejectsAFileThatIsNotABundle(t *testing.T) {
	sandboxUserEnv(t)
	good, _ := exportTestBundle(t)
	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"text":      []byte(strings.Repeat("this is not a tar archive\n", 40)),
		"truncated": raw[:len(raw)/2],
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name+".tar")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := runRepo(t, nil, "mirror", "verify", path)
			var ce *CLIError
			if !errors.As(err, &ce) {
				t.Fatalf("want a *CLIError, got %T: %v", err, err)
			}
			if want := path + " is not a polypkg bundle"; ce.Msg != want {
				t.Fatalf("Msg = %q, want %q", ce.Msg, want)
			}
			if !strings.Contains(ce.Hint, "export-bundle") {
				t.Fatalf("Hint = %q", ce.Hint)
			}
		})
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
	outDir, trustRoot, _ = buildUpstreamRepoReturningKey(t)
	return outDir, trustRoot
}

// buildUpstreamRepoReturningKey is buildUpstreamRepo plus the repo signing
// keypair (loaded back from the on-disk key the CLI `repo init` generated), so
// callers can sign additional upstream documents (e.g. a revocation list) that
// verify under the same trust root.
func buildUpstreamRepoReturningKey(t *testing.T) (outDir, trustRoot string, kp *repo.Keypair) {
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
	// Extract the key path the same way injectHelloPackage does, so we can load
	// the keypair `repo init` generated (there is no other handle to it).
	keyPath := ""
	for _, line := range splitLines(string(mraw)) {
		if len(line) > 10 && line[:10] == "    path: " {
			keyPath = line[10:]
			break
		}
	}
	if keyPath == "" {
		t.Fatalf("could not extract key path from manifest:\n%s", mraw)
	}
	if err := os.WriteFile(mPath, []byte(injectHelloPackage(t, repoDir, keyDir, mraw)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runRepo(t, env, "repo", "build", "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("build: %v", err)
	}
	kp, err = repo.LoadKey(keyPath, "pw")
	if err != nil {
		t.Fatalf("load upstream signing key: %v", err)
	}
	return filepath.Join(repoDir, "public"), filepath.Join(repoDir, "public", "trust_root.pub"), kp
}

// publishUpstreamRevocationList writes a repo-key-signed revocations.json (+
// .minisig) under the upstream's served output dir, mirroring
// internal/mirror/pull_test.go's publishRevocationList for the CLI package.
func publishUpstreamRevocationList(t *testing.T, upstreamDir string, kp *repo.Keypair, rl schema.RevocationList) {
	t.Helper()
	raw, err := json.Marshal(&rl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(upstreamDir, "revocations.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	sig := kp.SignRevocationList(rl.Serial, raw)
	if err := os.WriteFile(filepath.Join(upstreamDir, "revocations.json.minisig"), []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
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
		"packages:\n  " + pkgName + ":\n    - source: ./pkgs/" + pkgName + "\n"
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

// mirrorTrustSource reads the "source" field a mirror's own trust.json was
// published with. A consumer's Verifier must be bound to THIS name (the value
// the signed trust document claims), not to the --repo-source flag that
// produced it, so tests read it back rather than assuming the flag value.
func mirrorTrustSource(t *testing.T, outputDir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(outputDir, "trust.json"))
	if err != nil {
		t.Fatalf("read mirror trust.json: %v", err)
	}
	var doc struct {
		Source string `json:"source"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse mirror trust.json: %v", err)
	}
	if doc.Source == "" {
		t.Fatalf("mirror trust.json has no source field:\n%s", raw)
	}
	return doc.Source
}

// loadMirrorRevocations reads and verifies the mirror's published
// revocations.json under the mirror's OWN trust root (not the upstream's),
// proving propagation produced something a downstream consumer of this
// re-publishing mirror actually trusts.
func loadMirrorRevocations(t *testing.T, outputDir string) *trust.Revocations {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join(outputDir, "revocations.json"))
	if err != nil {
		t.Fatalf("mirror revocations.json missing: %v", err)
	}
	sig, err := os.ReadFile(filepath.Join(outputDir, "revocations.json.minisig"))
	if err != nil {
		t.Fatalf("mirror revocations.json.minisig missing: %v", err)
	}
	mirrorTrustRoot, err := os.ReadFile(filepath.Join(outputDir, "trust_root.pub"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := trust.NewVerifier("polypkg-native", string(mirrorTrustRoot), mirrorTrustSource(t, outputDir))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	revs, _, _, _, err := v.LoadRevocationList(doc, string(sig), 0, "")
	if err != nil {
		t.Fatalf("mirror revocation list rejected by consumer verifier: %v", err)
	}
	return revs
}

// TestMirrorPullPropagatesUpstreamRevocations is the end-to-end security proof
// for revocation propagation: an upstream revokes a hash + a builder key, and
// after `mirror pull`, the MIRROR's own revocations.json — verified under the
// mirror's own trust root, as a downstream consumer of the mirror would — honors
// both. runMirrorPull wires PropagateRevocations in; this proves the
// wiring actually produces a document a real consumer accepts, not just that
// the CLI call did not error.
func TestMirrorPullPropagatesUpstreamRevocations(t *testing.T) {
	upstreamDir, upTrustRoot, upKey := buildUpstreamRepoReturningKey(t)
	// Values chosen to be disjoint from anything the pull actually publishes, so
	// the inbound revocation gate (mirror.Pull refuses to launder a revoked
	// attestation/key it is about to carry) never fires and this pull succeeds.
	revHash := "blake3:" + strings.Repeat("a1", 32)
	revKey := "builder-unrelated"
	publishUpstreamRevocationList(t, upstreamDir, upKey, schema.RevocationList{
		Schema:              "polypkg.revocation-list/v1",
		Source:              "example",
		Serial:              1,
		Expires:             "2999-01-01T00:00:00Z",
		RevokedAttestations: []string{revHash},
		RevokedBuilderKeys:  []string{revKey},
	})

	keyPath, keyDir := makeLocalKey(t)
	outputDir := filepath.Join(t.TempDir(), "mirror")
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	if _, err := runRepo(t, env, "mirror", "pull",
		"--source-url", upstreamDir, "--trust-root", upTrustRoot, "--source-name", "example",
		"--repo-source", "local", "--output-dir", outputDir,
		"--key", keyPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("mirror pull: %v", err)
	}

	revs := loadMirrorRevocations(t, outputDir)
	if !revs.IsAttestationRevoked(revHash) {
		t.Fatalf("mirror does not honor upstream revoked attestation %s", revHash)
	}
	if !revs.IsBuilderKeyRevoked(revKey) {
		t.Fatalf("mirror does not honor upstream revoked builder key %s", revKey)
	}
}

// TestMirrorPullRevocationsAreCumulative proves the mirror's revocation list
// never auto-drops an entry: a second pull, from an upstream whose latest
// revocation list has dropped revHash (e.g. its retention window rolled it
// off), must still list revHash as revoked in the mirror's own re-published
// revocations.json. PropagateRevocations merges upstream's advertised set into
// the mirror's own history rather than replacing it (repo.mergedSets), so a
// once-seen revocation persists.
func TestMirrorPullRevocationsAreCumulative(t *testing.T) {
	upstreamDir, upTrustRoot, upKey := buildUpstreamRepoReturningKey(t)
	revHash := "blake3:" + strings.Repeat("a1", 32)
	revKey := "builder-unrelated"
	publishUpstreamRevocationList(t, upstreamDir, upKey, schema.RevocationList{
		Schema:              "polypkg.revocation-list/v1",
		Source:              "example",
		Serial:              1,
		Expires:             "2999-01-01T00:00:00Z",
		RevokedAttestations: []string{revHash},
		RevokedBuilderKeys:  []string{revKey},
	})

	keyPath, keyDir := makeLocalKey(t)
	outputDir := filepath.Join(t.TempDir(), "mirror")
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	if _, err := runRepo(t, env, "mirror", "pull",
		"--source-url", upstreamDir, "--trust-root", upTrustRoot, "--source-name", "example",
		"--repo-source", "local", "--output-dir", outputDir,
		"--key", keyPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("first mirror pull: %v", err)
	}
	if revs := loadMirrorRevocations(t, outputDir); !revs.IsAttestationRevoked(revHash) {
		t.Fatalf("fixture invalid: first pull did not propagate %s (test would be vacuous)", revHash)
	}

	// Upstream's NEXT revocation list drops revHash (still schema-valid: keeps
	// revKey so the document is non-empty) but the mirror must not forget it.
	publishUpstreamRevocationList(t, upstreamDir, upKey, schema.RevocationList{
		Schema:             "polypkg.revocation-list/v1",
		Source:             "example",
		Serial:             2,
		Expires:            "2999-01-01T00:00:00Z",
		RevokedBuilderKeys: []string{revKey},
	})
	if _, err := runRepo(t, env, "mirror", "pull",
		"--source-url", upstreamDir, "--trust-root", upTrustRoot, "--source-name", "example",
		"--repo-source", "local", "--output-dir", outputDir,
		"--key", keyPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("second mirror pull: %v", err)
	}

	revs := loadMirrorRevocations(t, outputDir)
	if !revs.IsAttestationRevoked(revHash) {
		t.Fatalf("mirror dropped a previously propagated revoked attestation %s once upstream stopped advertising it", revHash)
	}
	if !revs.IsBuilderKeyRevoked(revKey) {
		t.Fatalf("mirror does not honor still-advertised revoked builder key %s", revKey)
	}
}

func TestMirrorPullRejectsNonSlugRepoSource(t *testing.T) {
	for _, src := range []string{"../../pwned", "a/b", "..", "https://mymirror.local/repo"} {
		t.Run(src, func(t *testing.T) {
			_, err := runRepo(t, nil, "mirror", "pull",
				"--source-url", "file:///x", "--trust-root", "r.pub",
				"--repo-source", src, "--output-dir", t.TempDir(),
				"--key", filepath.Join(t.TempDir(), "k.key"))
			if err == nil {
				t.Fatalf("mirror pull must refuse --repo-source %q", src)
			}
			var ce *CLIError
			if !errors.As(err, &ce) {
				t.Fatalf("expected CLIError, got %T: %v", err, err)
			}
			if !strings.Contains(ce.Msg, "is not a valid slug") {
				t.Fatalf("want a slug error, got %q", ce.Msg)
			}
			if !strings.Contains(ce.Hint, "not a URL") {
				t.Fatalf("hint must say --repo-source takes a name, not a URL; got %q", ce.Hint)
			}
		})
	}
}

// A --key path that does not exist used to be reported byte-for-byte
// like a wrong passphrase, sending the operator after the password instead of
// the file. The two cases must now be distinguishable, and the missing-file one
// must name the path polypkg actually opened.
func TestMirrorPullMissingKeyFileIsNotReportedAsWrongPassword(t *testing.T) {
	upstream, upTrust := buildUpstreamRepo(t)
	keyPath, keyDir := makeLocalKey(t)
	absent := filepath.Join(keyDir, "not-there.key")
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}

	missingOut, missingErr := runRepo(t, env, "mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "example",
		"--repo-source", "local", "--output-dir", filepath.Join(t.TempDir(), "out"),
		"--key", absent, "--key-dir", keyDir)
	if missingErr == nil {
		t.Fatalf("expected mirror pull to fail with an absent --key (out=%s)", missingOut)
	}
	if !strings.Contains(missingErr.Error(), "signing key file not found") ||
		!strings.Contains(missingErr.Error(), absent) {
		t.Fatalf("missing-key error = %q, want it to say the file was not found and name %s", missingErr, absent)
	}

	badPwEnv := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "definitely-wrong"}
	wrongOut, wrongErr := runRepo(t, badPwEnv, "mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "example",
		"--repo-source", "local", "--output-dir", filepath.Join(t.TempDir(), "out"),
		"--key", keyPath, "--key-dir", keyDir)
	if wrongErr == nil {
		t.Fatalf("expected mirror pull to fail with a wrong password (out=%s)", wrongOut)
	}
	if !strings.Contains(wrongErr.Error(), "cannot unlock signing key") {
		t.Fatalf("wrong-password error = %q, want the unlock message", wrongErr)
	}
	if missingErr.Error() == wrongErr.Error() {
		t.Fatal("missing key file and wrong password produce identical errors")
	}
}

// mirror pull's --valid-for: the same non-positive window
// that repo build and repo revoke now refuse must be refused here too, before
// any upstream is fetched.
func TestMirrorPullRejectsNonPositiveValidFor(t *testing.T) {
	upstream, upTrust := buildUpstreamRepo(t)
	keyPath, keyDir := makeLocalKey(t)
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	outputDir := filepath.Join(t.TempDir(), "out")

	out, err := runRepo(t, env, "mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "example",
		"--repo-source", "local", "--output-dir", outputDir,
		"--key", keyPath, "--key-dir", keyDir, "--valid-for", "-1h")
	if err == nil {
		t.Fatalf("expected an error for --valid-for -1h (out=%s)", out)
	}
	if !strings.Contains(err.Error(), "--valid-for must be a positive duration") {
		t.Fatalf("error = %q, want it to name the flag", err)
	}
	if _, statErr := os.Stat(outputDir); statErr == nil {
		t.Fatal("a rejected --valid-for still published into --output-dir")
	}
}

// mirrorBuilderKeyID returns the id of the builder key the upstream's published
// trust bundle vouches for, so a revocation test has a real target.
func mirrorBuilderKeyID(t *testing.T, outputDir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(outputDir, "trust-bundle.json"))
	if err != nil {
		t.Fatalf("read carried trust bundle: %v", err)
	}
	tb, err := schema.ParseTrustBundle(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse carried trust bundle: %v", err)
	}
	if len(tb.BuilderKeys) == 0 {
		t.Fatal("carried trust bundle has no builder keys")
	}
	return tb.BuilderKeys[0].KeyID
}

// `mirror pull` used to write its generated polypkg-repo.yaml into the
// staging root, which defaults to a temp dir it deletes on the way out. The
// mirror therefore had no manifest, and `repo revoke` — the exact command
// docs/publishing.md tells the operator to run against it — could not open one.
// The manifest now lands in --output-dir and must actually drive the repo
// commands, not merely exist.
func TestMirrorPullWritesManageableManifestIntoOutputDir(t *testing.T) {
	upstream, upTrust := buildUpstreamRepoWithBundle(t)
	keyPath, keyDir := makeLocalKey(t)
	outputDir := filepath.Join(t.TempDir(), "local-repo")
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}

	out, err := runRepo(t, env, "mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "upstream",
		"--repo-source", "local", "--output-dir", outputDir,
		"--key", keyPath, "--key-dir", keyDir)
	if err != nil {
		t.Fatalf("mirror pull: %v (out=%s)", err, out)
	}

	mPath := filepath.Join(outputDir, "polypkg-repo.yaml")
	if _, statErr := os.Stat(mPath); statErr != nil {
		t.Fatalf("mirror pull left no polypkg-repo.yaml in --output-dir: %v", statErr)
	}

	// repo status must agree the mirror is up to date (exit 0), not error out on
	// a prebuilt artifact whose staging copy is gone.
	if sOut, sErr := runRepo(t, nil, "repo", "status", "--manifest", mPath, "--key-dir", keyDir); sErr != nil {
		t.Fatalf("repo status against the emitted manifest: %v (out=%s)", sErr, sOut)
	}

	// repo key show and repo export-bundle must both resolve through it.
	if kOut, kErr := runRepo(t, env, "repo", "key", "show", "--manifest", mPath, "--key-dir", keyDir); kErr != nil {
		t.Fatalf("repo key show: %v (out=%s)", kErr, kOut)
	}
	bundle := filepath.Join(t.TempDir(), "mirror.tar")
	if bOut, bErr := runRepo(t, env, "repo", "export-bundle", "--manifest", mPath, "--key-dir", keyDir, "-o", bundle); bErr != nil {
		t.Fatalf("repo export-bundle: %v (out=%s)", bErr, bOut)
	}
	if vErr := func() error {
		_, e := runRepo(t, nil, "mirror", "verify", bundle, "--trust-root", filepath.Join(outputDir, "trust_root.pub"))
		return e
	}(); vErr != nil {
		t.Fatalf("bundle exported via the emitted manifest does not verify: %v", vErr)
	}

	// The documented revocation-prune procedure must work end to end.
	keyID := mirrorBuilderKeyID(t, outputDir)
	if rOut, rErr := runRepo(t, env, "repo", "revoke", "--builder-key", keyID,
		"--manifest", mPath, "--key-dir", keyDir); rErr != nil {
		t.Fatalf("repo revoke --builder-key %s: %v (out=%s)", keyID, rErr, rOut)
	}
	rl := loadMirrorRevocations(t, outputDir)
	if !rl.IsBuilderKeyRevoked(keyID) {
		t.Fatalf("builder key %s is not in the published revocation list", keyID)
	}
	if rOut, rErr := runRepo(t, env, "repo", "revoke", "--remove-builder-key", keyID,
		"--manifest", mPath, "--key-dir", keyDir); rErr != nil {
		t.Fatalf("repo revoke --remove-builder-key %s: %v (out=%s)", keyID, rErr, rOut)
	}
}

// A rebuild through the emitted manifest must be a true no-op: it points at the
// published pool, so every package is a build-cache hit and the serial holds.
func TestMirrorPullEmittedManifestRebuildsAsNoOp(t *testing.T) {
	upstream, upTrust := buildUpstreamRepoWithBundle(t)
	keyPath, keyDir := makeLocalKey(t)
	outputDir := filepath.Join(t.TempDir(), "local-repo")
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}

	if out, err := runRepo(t, env, "mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "upstream",
		"--repo-source", "local", "--output-dir", outputDir,
		"--key", keyPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("mirror pull: %v (out=%s)", err, out)
	}
	before, err := os.ReadFile(filepath.Join(outputDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	mPath := filepath.Join(outputDir, "polypkg-repo.yaml")
	out, err := runRepo(t, env, "repo", "build", "--manifest", mPath, "--key-dir", keyDir)
	if err != nil {
		t.Fatalf("repo build through the emitted manifest: %v (out=%s)", err, out)
	}
	if !strings.Contains(out, "already up to date") {
		t.Fatalf("rebuild through the emitted manifest was not a no-op:\n%s", out)
	}
	after, err := os.ReadFile(filepath.Join(outputDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("rebuild rewrote the published index:\nbefore=%s\nafter=%s", before, after)
	}
	// The carried upstream builder keys must survive the rebuild.
	if _, statErr := os.Stat(filepath.Join(outputDir, "trust-bundle.json")); statErr != nil {
		t.Fatalf("rebuild dropped the carried trust bundle: %v", statErr)
	}
}

// docs/publishing.md's example passes relative --output-dir and --key. Those
// were written verbatim into a manifest that lives in the staging temp dir, so
// they resolved against /tmp/polypkg-mirror-pull-*; the pull published into the
// temp tree and deleted it. Absolute paths in the emitted manifest also make it
// usable from any cwd.
func TestMirrorPullResolvesRelativeOutputAndKeyAgainstCwd(t *testing.T) {
	upstream, upTrust := buildUpstreamRepo(t)
	work := t.TempDir()
	keyDir := filepath.Join(work, "keys")
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	kp, err := repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveKey(filepath.Join(keyDir, "local.key"), kp, "pw", repo.KDFScrypt); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}

	t.Chdir(work)
	if out, perr := runRepo(t, env, "mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "example",
		"--repo-source", "local", "--output-dir", "./mirror-repo",
		"--key", "./keys/local.key", "--key-dir", "./keys"); perr != nil {
		t.Fatalf("mirror pull with relative paths: %v (out=%s)", perr, out)
	}
	if _, statErr := os.Stat(filepath.Join(work, "mirror-repo", "index.json")); statErr != nil {
		t.Fatalf("relative --output-dir did not publish under the cwd: %v", statErr)
	}

	mPath := filepath.Join(work, "mirror-repo", "polypkg-repo.yaml")
	t.Chdir(t.TempDir()) // an unrelated cwd: only absolute paths can still resolve
	if out, sErr := runRepo(t, nil, "repo", "status", "--manifest", mPath, "--key-dir", keyDir); sErr != nil {
		t.Fatalf("repo status from an unrelated cwd: %v (out=%s)", sErr, out)
	}
	if out, kErr := runRepo(t, env, "repo", "key", "show", "--manifest", mPath, "--key-dir", keyDir); kErr != nil {
		t.Fatalf("repo key show from an unrelated cwd: %v (out=%s)", kErr, out)
	}
}

// mirrorPullArgs is the single-source `mirror pull` invocation the anti-rollback
// tests repeat against one upstream ("example") and one mirror ("local").
func mirrorPullArgs(upstream, upTrust, outputDir, keyPath, keyDir string) []string {
	return []string{"mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "example",
		"--repo-source", "local", "--output-dir", outputDir,
		"--key", keyPath, "--key-dir", keyDir}
}

// unrelatedRevocationList is a valid upstream revocation list at serial that
// revokes only a builder key the upstream does not use, so a pull carrying it
// succeeds.
func unrelatedRevocationList(serial uint64) schema.RevocationList {
	return schema.RevocationList{
		Schema:             "polypkg.revocation-list/v1",
		Source:             "example",
		Serial:             serial,
		Expires:            "2999-01-01T00:00:00Z",
		RevokedBuilderKeys: []string{"builder-unrelated"},
	}
}

// mirrorUpstreamFloors reads the floors mirror pull recorded for upstream
// "example" in mirror "local" under keyDir. ok is false when nothing was
// recorded. More than one record, or a record for any other upstream, fails the
// test.
func mirrorUpstreamFloors(t *testing.T, keyDir string) (seen trust.Seen, statePath string, ok bool) {
	t.Helper()
	stateHome := filepath.Join(keyDir, "local.mirror-state")
	names, err := trust.ListSeenSources(stateHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		return trust.Seen{}, "", false
	}
	if len(names) != 1 || !strings.HasPrefix(names[0], "example.") {
		t.Fatalf("mirror state records = %v, want exactly one example.<keyid>", names)
	}
	seen, err = trust.LoadSeen(stateHome, names[0])
	if err != nil {
		t.Fatal(err)
	}
	return seen, filepath.Join(stateHome, "trust", names[0]+".json"), true
}

func TestMirrorPullRecordsUpstreamFloorsUnderKeyDir(t *testing.T) {
	home := sandboxUserEnv(t)
	upstreamDir, upTrust, upKey := buildUpstreamRepoReturningKey(t)
	publishUpstreamRevocationList(t, upstreamDir, upKey, unrelatedRevocationList(1))
	keyPath, keyDir := makeLocalKey(t)
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}

	if out, err := runRepo(t, env, mirrorPullArgs(upstreamDir, upTrust, filepath.Join(t.TempDir(), "mirror"), keyPath, keyDir)...); err != nil {
		t.Fatalf("mirror pull: %v (out=%s)", err, out)
	}
	seen, _, ok := mirrorUpstreamFloors(t, keyDir)
	if !ok {
		t.Fatal("a successful pull recorded no upstream floors under --key-dir")
	}
	if seen.TrustSerial == 0 || seen.IndexSerial == 0 || seen.RevocationSerial != 1 {
		t.Fatalf("recorded floors = %+v, want non-zero trust/index and revocation serial 1", seen)
	}
	// The mirror's floors must not land in (or collide with) consumer state.
	if err := filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Base(filepath.Dir(p)) == "trust" {
			t.Errorf("mirror pull wrote trust state under the sandboxed HOME/XDG tree: %s", p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMirrorPullRefusesReplayedRevocationList(t *testing.T) {
	sandboxUserEnv(t)
	upstreamDir, upTrust, upKey := buildUpstreamRepoReturningKey(t)
	publishUpstreamRevocationList(t, upstreamDir, upKey, unrelatedRevocationList(1))
	oldDoc, err := os.ReadFile(filepath.Join(upstreamDir, "revocations.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldSig, err := os.ReadFile(filepath.Join(upstreamDir, "revocations.json.minisig"))
	if err != nil {
		t.Fatal(err)
	}
	keyPath, keyDir := makeLocalKey(t)
	outputDir := filepath.Join(t.TempDir(), "mirror")
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	args := mirrorPullArgs(upstreamDir, upTrust, outputDir, keyPath, keyDir)

	if out, err := runRepo(t, env, args...); err != nil {
		t.Fatalf("first mirror pull: %v (out=%s)", err, out)
	}
	publishUpstreamRevocationList(t, upstreamDir, upKey, unrelatedRevocationList(2))
	if out, err := runRepo(t, env, args...); err != nil {
		t.Fatalf("second mirror pull: %v (out=%s)", err, out)
	}

	// Replay the still-unexpired, validly signed serial-1 list.
	if err := os.WriteFile(filepath.Join(upstreamDir, "revocations.json"), oldDoc, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(upstreamDir, "revocations.json.minisig"), oldSig, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = runRepo(t, env, args...)
	if err == nil {
		t.Fatal("mirror pull accepted a replayed older revocation list")
	}
	var ce *CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("error = %T %v, want a *CLIError", err, err)
	}
	if want := `upstream "example" refused: revocation list serial 1 is below last-seen 2`; ce.Msg != want {
		t.Fatalf("Msg = %q, want %q", ce.Msg, want)
	}
	if !strings.Contains(ce.Err.Error(), "revocation list rollback: serial 1 is below last-seen 2") {
		t.Fatalf("Err = %v, want the full refusal kept in the chain", ce.Err)
	}
}

func TestMirrorPullRefusesStrippedRevocationList(t *testing.T) {
	sandboxUserEnv(t)
	upstreamDir, upTrust, upKey := buildUpstreamRepoReturningKey(t)
	publishUpstreamRevocationList(t, upstreamDir, upKey, unrelatedRevocationList(1))
	keyPath, keyDir := makeLocalKey(t)
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	args := mirrorPullArgs(upstreamDir, upTrust, filepath.Join(t.TempDir(), "mirror"), keyPath, keyDir)

	if out, err := runRepo(t, env, args...); err != nil {
		t.Fatalf("first mirror pull: %v (out=%s)", err, out)
	}
	for _, f := range []string{"revocations.json", "revocations.json.minisig"} {
		if err := os.Remove(filepath.Join(upstreamDir, f)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := runRepo(t, env, args...)
	if err == nil {
		t.Fatal("mirror pull accepted an upstream that stopped serving its revocation list")
	}
	// The refusal names the upstream and tells the operator which record to
	// delete, and where the reset is documented.
	var ce *CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("error = %T %v, want a *CLIError", err, err)
	}
	if want := `upstream "example" no longer publishes its revocation list (last seen at serial 1)`; ce.Msg != want {
		t.Fatalf("Msg = %q, want %q", ce.Msg, want)
	}
	if !strings.Contains(ce.Err.Error(), "revocation list absent but upstream previously published serial 1") {
		t.Fatalf("Err = %v, want the full refusal kept in the chain", ce.Err)
	}
	_, record, ok := mirrorUpstreamFloors(t, keyDir)
	if !ok {
		t.Fatal("fixture invalid: no record after the first pull")
	}
	if !strings.Contains(ce.Hint, record) || !strings.Contains(ce.Hint, "Resetting after an upstream is re-created") || !strings.Contains(ce.Hint, "docs/mirroring.md") {
		t.Fatalf("Hint = %q, want the record path %s and the docs/mirroring.md reset section", ce.Hint, record)
	}
}

// A run that fails after mirror.Pull verified newer documents (here: the local
// signing key will not unlock, which happens in repo.NewBuilder, after every
// upstream fetch) must leave the stored floors exactly where they were.
func TestMirrorPullStoresFloorsOnlyOnSuccess(t *testing.T) {
	sandboxUserEnv(t)
	upstreamDir, upTrust, upKey := buildUpstreamRepoReturningKey(t)
	publishUpstreamRevocationList(t, upstreamDir, upKey, unrelatedRevocationList(1))
	badPw := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "definitely-wrong"}

	// First-ever pull fails: nothing may be recorded.
	freshKeyPath, freshKeyDir := makeLocalKey(t)
	if _, err := runRepo(t, badPw, mirrorPullArgs(upstreamDir, upTrust, filepath.Join(t.TempDir(), "m1"), freshKeyPath, freshKeyDir)...); err == nil {
		t.Fatal("expected the wrong-password pull to fail")
	}
	if _, _, ok := mirrorUpstreamFloors(t, freshKeyDir); ok {
		t.Fatal("a failed first pull recorded upstream floors")
	}

	// A later pull fails after verifying a newer list: the floor must not move.
	keyPath, keyDir := makeLocalKey(t)
	outputDir := filepath.Join(t.TempDir(), "m2")
	if out, err := runRepo(t, map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}, mirrorPullArgs(upstreamDir, upTrust, outputDir, keyPath, keyDir)...); err != nil {
		t.Fatalf("baseline mirror pull: %v (out=%s)", err, out)
	}
	publishUpstreamRevocationList(t, upstreamDir, upKey, unrelatedRevocationList(2))
	if _, err := runRepo(t, badPw, mirrorPullArgs(upstreamDir, upTrust, outputDir, keyPath, keyDir)...); err == nil {
		t.Fatal("expected the wrong-password pull to fail")
	}
	seen, _, ok := mirrorUpstreamFloors(t, keyDir)
	if !ok || seen.RevocationSerial != 1 {
		t.Fatalf("floors after a failed run = %+v (recorded=%v), want revocation serial still 1", seen, ok)
	}
}

func TestMirrorPullFailsClosedOnCorruptState(t *testing.T) {
	sandboxUserEnv(t)
	upstreamDir, upTrust := buildUpstreamRepo(t)
	keyPath, keyDir := makeLocalKey(t)
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	args := mirrorPullArgs(upstreamDir, upTrust, filepath.Join(t.TempDir(), "mirror"), keyPath, keyDir)

	if out, err := runRepo(t, env, args...); err != nil {
		t.Fatalf("first mirror pull: %v (out=%s)", err, out)
	}
	_, statePath, ok := mirrorUpstreamFloors(t, keyDir)
	if !ok {
		t.Fatal("fixture invalid: first pull recorded no floors")
	}
	const garbage = "{not json"
	if err := os.WriteFile(statePath, []byte(garbage), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runRepo(t, env, args...)
	if err == nil {
		t.Fatal("mirror pull treated a corrupt state file as a first pull")
	}
	var ce *CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("error = %T %v, want a *CLIError", err, err)
	}
	// Msg is a sentence for the operator, not the JSON parser's complaint.
	if want := `cannot read the rollback record for upstream "example"`; ce.Msg != want {
		t.Fatalf("Msg = %q, want %q", ce.Msg, want)
	}
	if want := "the record at " + statePath + " is unreadable or damaged; restore it from backup, or delete it to re-baseline"; !strings.HasPrefix(ce.Hint, want) {
		t.Fatalf("Hint = %q, want it to start %q", ce.Hint, want)
	}
	if !strings.Contains(ce.Hint, "docs/mirroring.md") {
		t.Fatalf("Hint = %q, want it to point at docs/mirroring.md", ce.Hint)
	}
	if !strings.Contains(ce.Err.Error(), "parse trust state") {
		t.Fatalf("Err = %v, want the parse failure kept in the chain", ce.Err)
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != garbage {
		t.Fatalf("corrupt state file was rewritten to %q; it must be left for the operator", raw)
	}
}

// Under --fresh the build uses a throwaway cache, so repo.NewBuilder never
// checks --key-dir against --output-dir. The upstream anti-rollback state
// still goes to --key-dir, so the CLI itself must refuse a key dir inside the
// published tree, and any overlap between the published tree and the state
// dir, before any fetch, under --fresh or not.
func TestMirrorPullRefusesKeyDirInsideOutputDir(t *testing.T) {
	for _, tc := range []struct {
		name string
		// layout returns (outputDir, keyDir) under a fresh temp root.
		layout  func(root string) (outputDir, keyDir string)
		fresh   bool
		wantMsg string
	}{
		{"key dir under output, fresh", func(r string) (string, string) {
			return filepath.Join(r, "mirror"), filepath.Join(r, "mirror", "sub")
		}, true, "is inside --output-dir"},
		{"key dir under output", func(r string) (string, string) {
			return filepath.Join(r, "mirror"), filepath.Join(r, "mirror", "sub")
		}, false, "is inside --output-dir"},
		{"output is the state dir, fresh", func(r string) (string, string) {
			return filepath.Join(r, "keys", "local.mirror-state"), filepath.Join(r, "keys")
		}, true, "overlaps the mirror's anti-rollback state directory"},
		{"output is the state dir's trust records, fresh", func(r string) (string, string) {
			return filepath.Join(r, "keys", "local.mirror-state", "trust"), filepath.Join(r, "keys")
		}, true, "overlaps the mirror's anti-rollback state directory"},
		{"output under the state dir's trust records", func(r string) (string, string) {
			return filepath.Join(r, "keys", "local.mirror-state", "trust", "pub"), filepath.Join(r, "keys")
		}, false, "overlaps the mirror's anti-rollback state directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sandboxUserEnv(t)
			upstreamDir, upTrust := buildUpstreamRepo(t)
			keyPath, _ := makeLocalKey(t)
			outputDir, keyDir := tc.layout(t.TempDir())
			args := mirrorPullArgs(upstreamDir, upTrust, outputDir, keyPath, keyDir)
			if tc.fresh {
				args = append(args, "--fresh")
			}
			_, err := runRepo(t, map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}, args...)
			if err == nil {
				t.Fatal("mirror pull accepted an --output-dir that overlaps its private state")
			}
			var ce *CLIError
			if !errors.As(err, &ce) {
				t.Fatalf("error = %T %v, want a *CLIError", err, err)
			}
			if !strings.Contains(ce.Msg, keyDir) || !strings.Contains(ce.Msg, outputDir) || !strings.Contains(ce.Msg, tc.wantMsg) {
				t.Fatalf("Msg = %q, want %q naming both --key-dir %s and --output-dir %s", ce.Msg, tc.wantMsg, keyDir, outputDir)
			}
			if strings.Contains(ce.Msg, " puts ") {
				t.Fatalf("Msg = %q reads as the key dir putting itself somewhere", ce.Msg)
			}
			if ce.Hint == "" {
				t.Fatal("refusal carries no hint")
			}
			if _, statErr := os.Stat(outputDir); !errors.Is(statErr, fs.ErrNotExist) {
				t.Fatalf("refused pull wrote into --output-dir (stat: %v)", statErr)
			}
			if _, statErr := os.Stat(filepath.Join(keyDir, "local.mirror-state")); !errors.Is(statErr, fs.ErrNotExist) {
				t.Fatalf("refused pull created the state dir (stat: %v)", statErr)
			}
		})
	}
}

// The key's own directory may hold the published tree (key at /srv/m.key,
// output /srv/mirror-repo): nothing private is inside the output, and the
// state dir is a sibling of it.
func TestMirrorPullAllowsOutputDirBesideTheStateDir(t *testing.T) {
	sandboxUserEnv(t)
	upstreamDir, upTrust := buildUpstreamRepo(t)
	keyPath, keyDir := makeLocalKey(t)
	outputDir := filepath.Join(keyDir, "mirror-repo")
	if out, err := runRepo(t, map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}, mirrorPullArgs(upstreamDir, upTrust, outputDir, keyPath, keyDir)...); err != nil {
		t.Fatalf("mirror pull with --output-dir beside the state dir: %v (out=%s)", err, out)
	}
	if _, _, ok := mirrorUpstreamFloors(t, keyDir); !ok {
		t.Fatal("no floors recorded")
	}
}

// Two concurrent pulls into one mirror would race on the output dir and on the
// floor records, so a pull holds <state-dir>/lock for its whole run and fails
// fast when another holds it.
func TestMirrorPullFailsFastWhileAnotherPullHoldsTheLock(t *testing.T) {
	sandboxUserEnv(t)
	upstreamDir, upTrust := buildUpstreamRepo(t)
	keyPath, keyDir := makeLocalKey(t)
	outputDir := filepath.Join(t.TempDir(), "mirror")
	lockPath := filepath.Join(keyDir, "local.mirror-state", "lock")
	held, err := lock.Acquire(context.Background(), lockPath, lock.Options{TxID: "mirror-pull", Command: "polypkg mirror pull"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Release() }()

	_, err = runRepo(t, map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}, mirrorPullArgs(upstreamDir, upTrust, outputDir, keyPath, keyDir)...)
	if err == nil {
		t.Fatal("a second mirror pull ran while the first held the mirror lock")
	}
	var ce *CLIError
	if !errors.As(err, &ce) || !strings.Contains(ce.Msg, "another polypkg command is already running") {
		t.Fatalf("error = %T %v, want the lock-holder CLIError", err, err)
	}
	if _, statErr := os.Stat(outputDir); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("a pull refused on the lock wrote into --output-dir (stat: %v)", statErr)
	}
	if _, _, ok := mirrorUpstreamFloors(t, keyDir); ok {
		t.Fatal("a pull refused on the lock recorded floors")
	}
}

// An upstream URL with credentials must not leak into a mirror pull error.
func TestMirrorPullRedactsUpstreamCredentials(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	for _, tc := range []struct{ name, url string }{
		{"refused connection", "https://user:secret@127.0.0.1:9"},
		{"404", strings.Replace(srv.URL, "http://", "http://user:secret@", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sandboxUserEnv(t)
			_, upTrust := buildUpstreamRepo(t)
			keyPath, keyDir := makeLocalKey(t)
			out, err := runRepo(t, map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"},
				mirrorPullArgs(tc.url, upTrust, filepath.Join(t.TempDir(), "mirror"), keyPath, keyDir)...)
			if err == nil {
				t.Fatal("expected the pull to fail")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(out, "secret") {
				t.Fatalf("mirror pull leaked the URL password: err=%q out=%q", err, out)
			}
			var ce *CLIError
			if errors.As(err, &ce) && strings.Contains(ce.Msg, "secret") {
				t.Fatalf("CLIError.Msg leaked the URL password: %q", ce.Msg)
			}
			if !strings.Contains(err.Error(), "://xxxxx@") || strings.Contains(err.Error(), "user") {
				t.Fatalf("error = %q, want the redacted URL", err)
			}
		})
	}
}

// The per-upstream stderr notes (freshness grace, narrowing) name the upstream
// by URL, so they must redact a token in it too.
func TestMirrorPullRedactsTheUpstreamURLInStderrNotes(t *testing.T) {
	sandboxUserEnv(t)
	upstreamDir, upTrust, upKey := buildUpstreamRepoReturningKey(t)
	expired := unrelatedRevocationList(1)
	expired.Expires = "2000-01-01T00:00:00Z"
	publishUpstreamRevocationList(t, upstreamDir, upKey, expired)
	srv := httptest.NewServer(http.FileServer(http.Dir(upstreamDir)))
	defer srv.Close()
	tokenURL := strings.Replace(srv.URL, "http://", "http://ghp_secret@", 1)
	keyPath, keyDir := makeLocalKey(t)

	args := append(mirrorPullArgs(tokenURL, upTrust, filepath.Join(t.TempDir(), "mirror"), keyPath, keyDir),
		"--accept-expiry-until", "2999-01-01T00:00:00Z")
	out, err := runRepo(t, map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}, args...)
	if err != nil {
		t.Fatalf("mirror pull: %v (out=%s)", err, out)
	}
	if !strings.Contains(out, "SECURITY: upstream http://xxxxx@") {
		t.Fatalf("output lacks the grace note with the redacted URL:\n%s", out)
	}
	if strings.Contains(out, "ghp_secret") {
		t.Fatalf("output leaks the URL token:\n%s", out)
	}
}

// A mirror operator who names the upstream wrongly is told to fix
// --source-name, not given the client-side `source add` remedy.
func TestMirrorPullSourceNameMismatchPointsAtSourceName(t *testing.T) {
	upstream, upTrust := buildUpstreamRepo(t) // publishes source "example"
	keyPath, keyDir := makeLocalKey(t)
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}

	_, err := runRepo(t, env, "mirror", "pull",
		"--source-url", upstream, "--trust-root", upTrust, "--source-name", "upstream",
		"--repo-source", "local", "--output-dir", filepath.Join(t.TempDir(), "out"),
		"--key", keyPath, "--key-dir", keyDir)
	var ce *CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("want a *CLIError, got %T: %v", err, err)
	}
	if !strings.Contains(ce.Msg, `trust document is for source "example", expected "upstream"`) {
		t.Fatalf("Msg = %q", ce.Msg)
	}
	if !strings.Contains(ce.Hint, "--source-name example") || !strings.Contains(ce.Hint, "source_name: example") {
		t.Fatalf("Hint = %q, want the --source-name remedy", ce.Hint)
	}
	if strings.Contains(ce.Hint, "polypkg source add") {
		t.Fatalf("Hint = %q gives the client-side remedy", ce.Hint)
	}
}

// A bundle checked against a trust root that did not sign it gets a hint
// that says what the library's "Incompatible key identifiers" means.
func TestMirrorVerifyWrongTrustRootExplainsTheSignatureFailure(t *testing.T) {
	bundle, _ := exportTestBundle(t)
	kp, err := repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(t.TempDir(), "wrong.pub")
	if err := os.WriteFile(wrong, []byte(kp.PublicKeyFile("unrelated key")), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = runRepo(t, nil, "mirror", "verify", bundle, "--trust-root", wrong)
	var ce *CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("want a *CLIError, got %T: %v", err, err)
	}
	if !strings.Contains(ce.Msg, "pool manifest signature") {
		t.Fatalf("Msg = %q", ce.Msg)
	}
	if !strings.Contains(ce.Hint, "signed by another key") || !strings.Contains(ce.Hint, "Recovering after a repository is re-created") {
		t.Fatalf("Hint = %q", ce.Hint)
	}
}

// Without --trust-root the bundle is checked only against the trust root it
// carries itself, which proves consistency, not who signed it.
func TestMirrorVerifySaysWhenItOnlyCheckedSelfConsistency(t *testing.T) {
	bundle, root := exportTestBundle(t)

	out, err := runRepo(t, nil, "mirror", "verify", bundle)
	if err != nil {
		t.Fatalf("mirror verify: %v (out=%s)", err, out)
	}
	if !strings.Contains(out, "OK:") || !strings.Contains(out, "self-consistency only") {
		t.Fatalf("an unpinned verify must say it checked self-consistency only, got %q", out)
	}

	out, err = runRepo(t, nil, "mirror", "verify", bundle, "--trust-root", root)
	if err != nil {
		t.Fatalf("mirror verify --trust-root: %v (out=%s)", err, out)
	}
	if strings.Contains(out, "self-consistency") {
		t.Fatalf("a pinned verify must not be qualified, got %q", out)
	}

	out, err = runRepo(t, nil, "--format", "json", "mirror", "verify", bundle)
	if err != nil {
		t.Fatalf("mirror verify json: %v (out=%s)", err, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	res, err := schema.ParseCLIResult(strings.NewReader(lines[len(lines)-1]))
	if err != nil {
		t.Fatalf("parse result: %v (out=%s)", err, out)
	}
	if res.Data["pinned"] != false {
		t.Fatalf("data.pinned = %v, want false", res.Data["pinned"])
	}
}
