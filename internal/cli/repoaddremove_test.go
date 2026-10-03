package cli

import (
	"bytes"
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

// readManifestBytes returns the raw manifest so a test can prove a rejected
// command left it byte-for-byte unchanged, rather than only checking that some
// key is still present.
func readManifestBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest %s: %v", path, err)
	}
	return b
}

// assertNoPendingChanges fails unless `repo status` exits 0. A manifest edit
// staged by a command that then exited non-zero shows up here as exit 2 — the
// state that makes the next bare `repo build` publish something nobody asked
// for.
func assertNoPendingChanges(t *testing.T, mPath, keyDir string) {
	t.Helper()
	out, err := runRepo(t, nil, "repo", "status", "--manifest", mPath, "--key-dir", keyDir)
	if code := exitCodeOf(err); code != 0 {
		t.Fatalf("`repo status` = exit %d, want 0 (out=%s err=%v)", code, out, err)
	}
}

// TestRepoRemoveRejectedValidForLeavesManifestUnchanged pins the invariant that
// a `repo remove` which exits non-zero has not modified polypkg-repo.yaml.
// --valid-for used to be read inside buildRepo, downstream of the manifest
// write, so `repo remove hello --valid-for 0` failed loudly *after* deleting
// hello from the manifest — staging an unpublish that the next bare
// `repo build` would carry out.
func TestRepoRemoveRejectedValidForLeavesManifestUnchanged(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")

	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}
	pkgDir := writeHelloPkgSource(t, repoDir)
	if _, err := runRepo(t, env, "repo", "add", pkgDir, "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("repo add: %v", err)
	}
	before := readManifestBytes(t, mPath)

	for _, bad := range []string{"0", "-1h"} {
		t.Run("valid-for="+bad, func(t *testing.T) {
			out, err := runRepo(t, env, "repo", "remove", "hello",
				"--manifest", mPath, "--key-dir", keyDir, "--valid-for", bad)
			if err == nil {
				t.Fatalf("--valid-for %s: expected an error, got success (out=%s)", bad, out)
			}
			if !strings.Contains(err.Error(), "--valid-for must be a positive duration") {
				t.Fatalf("--valid-for %s: error = %q, want it to name the flag", bad, err)
			}
			if after := readManifestBytes(t, mPath); !bytes.Equal(before, after) {
				t.Fatalf("rejected `repo remove` rewrote the manifest\nbefore:\n%s\nafter:\n%s", before, after)
			}
			assertNoPendingChanges(t, mPath, keyDir)
		})
	}
}

// TestRepoAddRejectedValidForLeavesManifestUnchanged is the `repo add` half of
// the same invariant: a rejected window must not stage a new package.
func TestRepoAddRejectedValidForLeavesManifestUnchanged(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")

	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Build the empty repository so `repo status` has a clean baseline to
	// compare against (an unbuilt repo is pending by definition).
	if _, err := runRepo(t, env, "repo", "build", "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("repo build: %v", err)
	}
	pkgDir := writeHelloPkgSource(t, repoDir)
	before := readManifestBytes(t, mPath)

	for _, bad := range []string{"0", "-1h"} {
		t.Run("valid-for="+bad, func(t *testing.T) {
			out, err := runRepo(t, env, "repo", "add", pkgDir,
				"--manifest", mPath, "--key-dir", keyDir, "--valid-for", bad)
			if err == nil {
				t.Fatalf("--valid-for %s: expected an error, got success (out=%s)", bad, out)
			}
			if !strings.Contains(err.Error(), "--valid-for must be a positive duration") {
				t.Fatalf("--valid-for %s: error = %q, want it to name the flag", bad, err)
			}
			if after := readManifestBytes(t, mPath); !bytes.Equal(before, after) {
				t.Fatalf("rejected `repo add` rewrote the manifest\nbefore:\n%s\nafter:\n%s", before, after)
			}
			assertNoPendingChanges(t, mPath, keyDir)
		})
	}
}

// TestRepoAddRemoveRejectedKeyPasswordLeavesManifestUnchanged covers the other
// two ways add/remove used to fail after the manifest write: no password source
// at all, and a password that will not unlock the signing key. Both are decided
// before the edit now, so the manifest survives either.
func TestRepoAddRemoveRejectedKeyPasswordLeavesManifestUnchanged(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")

	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}
	pkgDir := writeHelloPkgSource(t, repoDir)
	if _, err := runRepo(t, env, "repo", "add", pkgDir, "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("repo add: %v", err)
	}
	// A second package source, so the `add` cases have something new to stage.
	otherDir := filepath.Join(repoDir, "pkgs", "goodbye")
	if err := os.MkdirAll(filepath.Join(otherDir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(otherDir, "polypkg.yaml"),
		[]byte("schema: polypkg.package/v1\nname: goodbye\nversion: 1.0.0\nactions: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(otherDir, "content", "bin", "goodbye"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	before := readManifestBytes(t, mPath)

	cases := []struct {
		name string
		pw   string
		args []string
	}{
		{"add/no-password", "", []string{"repo", "add", otherDir}},
		{"add/wrong-password", "definitely-not-pw", []string{"repo", "add", otherDir}},
		{"remove/no-password", "", []string{"repo", "remove", "hello"}},
		{"remove/wrong-password", "definitely-not-pw", []string{"repo", "remove", "hello"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append(append([]string{}, tc.args...), "--manifest", mPath, "--key-dir", keyDir)
			out, err := runRepo(t, map[string]string{"POLYPKG_REPO_KEY_PASSWORD": tc.pw}, args...)
			if err == nil {
				t.Fatalf("expected an error, got success (out=%s)", out)
			}
			if after := readManifestBytes(t, mPath); !bytes.Equal(before, after) {
				t.Fatalf("rejected command rewrote the manifest\nbefore:\n%s\nafter:\n%s", before, after)
			}
			assertNoPendingChanges(t, mPath, keyDir)
		})
	}
}

// TestRepoAddRemoveValidValidForStillPublishes is the control for the
// invariant tests above: moving validation ahead of the manifest write must not
// stop a well-formed --valid-for from being honored end to end.
func TestRepoAddRemoveValidValidForStillPublishes(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")

	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}
	pkgDir := writeHelloPkgSource(t, repoDir)

	out, err := runRepo(t, env, "repo", "add", pkgDir, "--manifest", mPath, "--key-dir", keyDir, "--valid-for", "800h")
	if err != nil {
		t.Fatalf("repo add --valid-for 800h: %v (out=%s)", err, out)
	}
	if _, serr := os.Stat(publishedArtifactPath(t, filepath.Join(repoDir, "public"), "hello")); serr != nil {
		t.Fatalf("artifact missing after add: %v", serr)
	}
	assertNoPendingChanges(t, mPath, keyDir)

	out, err = runRepo(t, env, "repo", "remove", "hello", "--manifest", mPath, "--key-dir", keyDir, "--valid-for", "800h")
	if err != nil {
		t.Fatalf("repo remove --valid-for 800h: %v (out=%s)", err, out)
	}
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
		t.Fatal("index still references hello after a successful remove")
	}
	assertNoPendingChanges(t, mPath, keyDir)
}

// writeUnpackablePkgSource writes a package source that passes every check
// `repo add` makes before it builds — polypkg.yaml parses and names a version —
// but that PackArtifact refuses, because symlinks under content/ are not
// packable. It is the cheapest way to fail a build *after* validation, which is
// the window in which a manifest edit used to survive on disk.
//
// Returns the source dir and the symlink path, so the caller can clear the
// impediment and prove the same command succeeds and persists.
func writeUnpackablePkgSource(t *testing.T, root string) (pkgDir, symlink string) {
	t.Helper()
	pkgDir = filepath.Join(root, "pkgs", "unpackable")
	if err := os.MkdirAll(filepath.Join(pkgDir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "polypkg.yaml"),
		[]byte("schema: polypkg.package/v1\nname: unpackable\nversion: 1.0.0\nactions: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "content", "bin", "real"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	symlink = filepath.Join(pkgDir, "content", "bin", "link")
	if err := os.Symlink("real", symlink); err != nil {
		t.Fatal(err)
	}
	return pkgDir, symlink
}

// TestRepoAddFailedBuildLeavesManifestUnchanged extends the add/remove invariant
// past the validation phase: a `repo add` that fails *while building* must also
// leave polypkg-repo.yaml byte-identical. The manifest edit used to be written
// before the reconcile, so a pack, sign, or I/O failure left the operator with
// an error, an unbuilt repository, and a staged edit that the next bare
// `repo build` would publish.
func TestRepoAddFailedBuildLeavesManifestUnchanged(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")

	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}
	helloDir := writeHelloPkgSource(t, repoDir)
	if _, err := runRepo(t, env, "repo", "add", helloDir, "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("repo add hello: %v", err)
	}
	before := readManifestBytes(t, mPath)

	badDir, symlink := writeUnpackablePkgSource(t, repoDir)
	out, err := runRepo(t, env, "repo", "add", badDir, "--manifest", mPath, "--key-dir", keyDir)
	if err == nil {
		t.Fatalf("expected the build to fail on an unpackable source, got success (out=%s)", out)
	}
	if !strings.Contains(err.Error(), "cannot pack package") {
		t.Fatalf("error = %q, want the pack failure", err)
	}
	if after := readManifestBytes(t, mPath); !bytes.Equal(before, after) {
		t.Fatalf("`repo add` that failed to build rewrote the manifest\nbefore:\n%s\nafter:\n%s", before, after)
	}
	assertNoPendingChanges(t, mPath, keyDir)

	// Control: with the impediment cleared, the same command succeeds and the
	// edit does land. Persisting on success is the other half of the invariant.
	if err := os.Remove(symlink); err != nil {
		t.Fatal(err)
	}
	if out, err := runRepo(t, env, "repo", "add", badDir, "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("repo add after clearing the symlink: %v (out=%s)", err, out)
	}
	if after := readManifestBytes(t, mPath); bytes.Equal(before, after) {
		t.Fatalf("a successful `repo add` must persist the edit; manifest is unchanged:\n%s", after)
	}
	if _, err := os.Stat(publishedArtifactPath(t, filepath.Join(repoDir, "public"), "unpackable")); err != nil {
		t.Fatalf("artifact missing after the successful add: %v", err)
	}
	assertNoPendingChanges(t, mPath, keyDir)
}

// TestRepoRemoveFailedBuildLeavesManifestUnchanged is the `repo remove` half of
// the same invariant, driven by a publish-time I/O failure (a read-only output
// directory) rather than a pack failure, so both sides of the reconcile are
// covered.
func TestRepoRemoveFailedBuildLeavesManifestUnchanged(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("a read-only output directory does not stop root")
	}
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")
	pubDir := filepath.Join(repoDir, "public")

	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}
	helloDir := writeHelloPkgSource(t, repoDir)
	if _, err := runRepo(t, env, "repo", "add", helloDir, "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("repo add hello: %v", err)
	}
	before := readManifestBytes(t, mPath)

	// Publishing stages every metadata file as a temp sibling before renaming
	// any of it into place, so a read-only output directory fails the build with
	// the previously published set fully intact.
	if err := os.Chmod(pubDir, 0o555); err != nil {
		t.Fatal(err)
	}
	out, rmErr := runRepo(t, env, "repo", "remove", "hello", "--manifest", mPath, "--key-dir", keyDir)
	if err := os.Chmod(pubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if rmErr == nil {
		t.Fatalf("expected the build to fail against a read-only output dir, got success (out=%s)", out)
	}
	if after := readManifestBytes(t, mPath); !bytes.Equal(before, after) {
		t.Fatalf("`repo remove` that failed to build rewrote the manifest\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if _, err := os.Stat(publishedArtifactPath(t, pubDir, "hello")); err != nil {
		t.Fatalf("failed remove must leave hello published: %v", err)
	}
	assertNoPendingChanges(t, mPath, keyDir)

	// Control: the same removal succeeds once the output dir is writable again.
	if out, err := runRepo(t, env, "repo", "remove", "hello", "--manifest", mPath, "--key-dir", keyDir); err != nil {
		t.Fatalf("repo remove after restoring permissions: %v (out=%s)", err, out)
	}
	if after := readManifestBytes(t, mPath); bytes.Equal(before, after) {
		t.Fatalf("a successful `repo remove` must persist the edit; manifest is unchanged:\n%s", after)
	}
	assertNoPendingChanges(t, mPath, keyDir)
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
