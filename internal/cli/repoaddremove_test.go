package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func TestRepoAddBuildsThenRemoveRebuilds(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")

	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}
	pkgDir := writeHelloPkgSource(t, repoDir) // root/pkgs/hello

	if _, err := runRepo(t, env, "repo", "add", pkgDir, "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("repo add: %v", err)
	}
	if _, err := os.Stat(publishedArtifactPath(t, filepath.Join(repoDir, "public"), "hello")); err != nil {
		t.Fatalf("artifact missing after add: %v", err)
	}
	// Manifest now lists hello.
	if f, err := os.Open(mPath); err == nil {
		m, perr := schema.ParseRepoManifest(f)
		f.Close()
		if perr != nil {
			t.Fatal(perr)
		}
		if _, ok := m.Packages["hello"]; !ok {
			t.Fatal("manifest missing hello after add")
		}
	} else {
		t.Fatal(err)
	}

	if _, err := runRepo(t, env, "repo", "remove", "hello", "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("repo remove: %v", err)
	}
	// index.json no longer references hello.
	idxRaw, err := os.ReadFile(filepath.Join(repoDir, "public", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx struct {
		Packages map[string]any `json:"packages"`
	}
	if err := json.Unmarshal(idxRaw, &idx); err != nil {
		t.Fatal(err)
	}
	if _, ok := idx.Packages["hello"]; ok {
		t.Fatal("index still references hello after remove")
	}
}

func TestRepoAddBadSourceErrors(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")

	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}

	// An empty directory has no polypkg.yaml, so ReadPackageSource must fail.
	emptyDir := t.TempDir()
	_, err := runRepo(t, env, "repo", "add", emptyDir, "--manifest", mPath, "--key-dir", keyDir)
	if err == nil {
		t.Fatal("expected error for missing polypkg.yaml, got nil")
	}
	var cliErr *CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("expected *CLIError, got %T: %v", err, err)
	}
	if !strings.Contains(cliErr.Hint, "polypkg.yaml") {
		t.Fatalf("CLIError.Hint should mention polypkg.yaml; got %q", cliErr.Hint)
	}
}

// TestRepoAddNormalizesSrcPathRelativeToManifest verifies that `repo add` stores
// the package source path relative to the manifest directory, so that Build
// resolves it correctly even when `repo add` is invoked from a different cwd.
// We simulate this by passing an absolute path for --manifest and an absolute
// path for the source dir, then confirming the artifact is published.
func TestRepoAddNormalizesSrcPathRelativeToManifest(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")

	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Place the package source outside the repo dir to exercise path normalization.
	pkgRoot := t.TempDir()
	pkgDir := filepath.Join(pkgRoot, "hello")
	if err := os.MkdirAll(filepath.Join(pkgDir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "polypkg.yaml"), []byte("schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "content", "bin", "hello"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Run repo add with an absolute manifest path and absolute source path.
	// The source is outside the repo dir — normalizeSrcPath must store an absolute
	// path (since relative would traverse with "..") that Build can use.
	if _, err := runRepo(t, env, "repo", "add", pkgDir, "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("repo add: %v", err)
	}
	if _, err := os.Stat(publishedArtifactPath(t, filepath.Join(repoDir, "public"), "hello")); err != nil {
		t.Fatalf("artifact missing after add with external source dir: %v", err)
	}
}

func TestRepoKeyShowPrintsPublicKeyNotSecret(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")
	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatal(err)
	}
	out, err := runRepo(t, env, "repo", "key", "show", "--manifest", mPath, "--key-dir", keyDir)
	if err != nil {
		t.Fatalf("repo key show: %v", err)
	}
	if !strings.Contains(out, "untrusted comment") {
		t.Fatalf("key show should print the public key file; got %q", out)
	}
	if strings.Contains(out, "ciphertext") || strings.Contains(strings.ToLower(out), "private") {
		t.Fatalf("key show leaked secret material: %q", out)
	}
}
