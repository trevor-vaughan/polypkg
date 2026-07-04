package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// writeHelloPkgSource writes a minimal package source dir under root/pkgs/hello.
func writeHelloPkgSource(t *testing.T, root string) string {
	t.Helper()
	pkgDir := filepath.Join(root, "pkgs", "hello")
	if err := os.MkdirAll(filepath.Join(pkgDir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "polypkg.yaml"), []byte("schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "content", "bin", "hello"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return pkgDir
}

func TestRepoBuildPublishesAndStatusExitCodes(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")

	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Register a package by writing a hello source tree and injecting it into
	// the manifest. Because yaml.Marshal omits the empty Packages field via
	// omitempty, the manifest written by init has no packages entry. We
	// therefore rewrite the manifest wholesale with the known values so the
	// test is not fragile against serialization order or whitespace.
	writeHelloPkgSource(t, repoDir)

	// Read the manifest to discover the key path (it embeds the absolute key
	// path), then rewrite it with the hello package added.
	mraw, err := os.ReadFile(mPath)
	if err != nil {
		t.Fatal(err)
	}
	updated := injectHelloPackage(t, repoDir, keyDir, mraw)
	if err := os.WriteFile(mPath, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}

	// status BEFORE build → pending → exit code 2. No password needed.
	_, statusErr := runRepo(t, nil, "repo", "status", "--manifest", mPath, "--key-dir", keyDir)
	if code := exitCodeOf(statusErr); code != 2 {
		t.Fatalf("status before build: want exit 2, got %d (err %v)", code, statusErr)
	}

	// build → publishes artifacts (requires password).
	if _, err := runRepo(t, env, "repo", "build", "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := os.Stat(publishedArtifactPath(t, filepath.Join(repoDir, "public"), "hello")); err != nil {
		t.Fatalf("artifact not published: %v", err)
	}

	// status AFTER build → clean → exit 0. No password needed.
	if _, err := runRepo(t, nil, "repo", "status", "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("status after build should be clean (exit 0), got %v", err)
	}
}

// injectHelloPackage rewrites the manifest content to add the hello package.
// It extracts the key path from the existing manifest bytes and constructs a
// fresh manifest so we are immune to field-order or whitespace changes.
func injectHelloPackage(t *testing.T, repoDir, keyDir string, existing []byte) string {
	t.Helper()
	// Extract key path from existing manifest (line starting with "    path: ").
	keyPath := ""
	for _, line := range splitLines(string(existing)) {
		if len(line) > 10 && line[:10] == "    path: " {
			keyPath = line[10:]
			break
		}
	}
	if keyPath == "" {
		t.Fatalf("could not extract key path from manifest:\n%s", existing)
	}
	return fmt.Sprintf(`schema: polypkg.repo/v1
source: example
output: ./public
key:
    path: %s
    kdf: scrypt
packages:
    hello:
        source: ./pkgs/hello
`, keyPath)
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// exitCodeOf extracts the StatusError exit code, or 0 for nil, or 1 otherwise.
func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return 1
}

// TestRepoStatusNeedsNoPassword proves that `repo status` works without any
// signing-key password — it is a read-only probe and must never decrypt the key.
func TestRepoStatusNeedsNoPassword(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	pwEnv := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")

	// Initialise the repo with a password (key generation requires it).
	if _, err := runRepo(t, pwEnv, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Add a hello package to the manifest.
	writeHelloPkgSource(t, repoDir)
	mraw, err := os.ReadFile(mPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mPath, []byte(injectHelloPackage(t, repoDir, keyDir, mraw)), 0o644); err != nil {
		t.Fatal(err)
	}

	// status with NO password env and NO --key-password-file must succeed
	// (exit 2 = pending, not 1 = error).
	_, statusErr := runRepo(t, nil, "repo", "status", "--manifest", mPath, "--key-dir", keyDir)
	if code := exitCodeOf(statusErr); code != 2 {
		t.Fatalf("status without password: want exit 2 (pending), got %d (err=%v)", code, statusErr)
	}

	// Build to bring the repo up to date (requires password).
	if _, err := runRepo(t, pwEnv, "repo", "build", "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("build: %v", err)
	}

	// status after build with NO password must exit 0 (clean).
	if _, err := runRepo(t, nil, "repo", "status", "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("status after build without password: want exit 0, got %v", err)
	}
}
