package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/archive"
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

// helloBuild is one hello package source for setupHelloBuilds: its directory
// under <repo>/pkgs, its version, and its platform ("" for platform-agnostic).
type helloBuild struct{ sub, version, platform string }

// setupHelloBuilds initialises a repository and registers one hello source per
// build with `repo add`, in order, so each lands in polypkg-repo.yaml as
// "pkgs/<sub>". Returns the manifest path, key dir, and env for runRepo.
func setupHelloBuilds(t *testing.T, builds ...helloBuild) (mPath, keyDir string, env map[string]string) {
	t.Helper()
	sandboxUserEnv(t)
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir = t.TempDir()
	env = map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath = filepath.Join(repoDir, "polypkg-repo.yaml")
	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}
	for _, b := range builds {
		dir := writeHelloBuild(t, repoDir, b)
		if out, err := runRepo(t, env, "repo", "add", dir, "--manifest", mPath, "--key-dir", keyDir); err != nil {
			t.Fatalf("repo add %s: %v (out=%s)", b.sub, err, out)
		}
	}
	return mPath, keyDir, env
}

// writeHelloBuild writes the hello package source b describes under
// <repoDir>/pkgs/<b.sub> and returns that directory. Its content names b.sub,
// so every build packs to a distinct artifact.
func writeHelloBuild(t *testing.T, repoDir string, b helloBuild) string {
	t.Helper()
	dir := filepath.Join(repoDir, "pkgs", b.sub)
	if err := os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	recipe := "schema: polypkg.package/v1\nname: hello\nversion: " + b.version + "\n"
	if b.platform != "" {
		recipe += "platform: " + b.platform + "\n"
	}
	recipe += "actions: []\n"
	if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(recipe), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "content", "bin", "hello"),
		[]byte("#!/bin/sh\necho "+b.sub+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// manifestHelloSources returns the source of every hello entry in the
// manifest at mPath, in manifest order.
func manifestHelloSources(t *testing.T, mPath string) []string {
	t.Helper()
	f, err := os.Open(mPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := schema.ParseRepoManifest(f)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(m.Packages["hello"]))
	for _, e := range m.Packages["hello"] {
		got = append(got, e.Source)
	}
	return got
}

// publishedHelloVersions returns the version of every hello entry in the
// published index beside the manifest at mPath, in index order.
func publishedHelloVersions(t *testing.T, mPath string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(mPath), "public", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx struct {
		Packages map[string][]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(idx.Packages["hello"]))
	for _, e := range idx.Packages["hello"] {
		got = append(got, e.Version)
	}
	return got
}

// removedJSON is one element of `repo remove`'s data.removed list.
type removedJSON struct {
	Entry    string `json:"entry"`
	Platform string `json:"platform"`
}

// repoRemoveJSON is the --format json envelope `repo remove` emits.
type repoRemoveJSON struct {
	Status string `json:"status"`
	Data   struct {
		Package string        `json:"package"`
		Version string        `json:"version"`
		Serial  uint64        `json:"serial"`
		Removed []removedJSON `json:"removed"`
	} `json:"data"`
}

// TestRepoRemoveVersionWithdrawsEveryPlatform pins the user decision: `@<version>`
// withdraws every platform build of that version, reports each one, and leaves
// the package's other versions published.
func TestRepoRemoveVersionWithdrawsEveryPlatform(t *testing.T) {
	mPath, keyDir, env := setupHelloBuilds(t,
		helloBuild{"a", "1.0.0", "linux/amd64"},
		helloBuild{"b", "1.0.0", "darwin/arm64"},
		helloBuild{"c", "2.0.0", ""})

	out, err := runRepo(t, env, "repo", "remove", "hello@1.0.0",
		"--manifest", mPath, "--key-dir", keyDir, "--format", "json")
	if err != nil {
		t.Fatalf("repo remove: %v (out=%s)", err, out)
	}
	var res repoRemoveJSON
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	want := []removedJSON{{"pkgs/a", "linux/amd64"}, {"pkgs/b", "darwin/arm64"}}
	if res.Status != "ok" || res.Data.Package != "hello" || res.Data.Version != "1.0.0" ||
		res.Data.Serial == 0 || !slices.Equal(res.Data.Removed, want) {
		t.Fatalf("result = %+v, want both 1.0.0 builds removed: %+v", res, want)
	}
	if got := manifestHelloSources(t, mPath); !slices.Equal(got, []string{"pkgs/c"}) {
		t.Fatalf("manifest hello sources = %v, want [pkgs/c]", got)
	}
	if got := publishedHelloVersions(t, mPath); !slices.Equal(got, []string{"2.0.0"}) {
		t.Fatalf("published hello versions = %v, want [2.0.0]", got)
	}
}

// TestRepoRemoveVersionListsEveryPlatformInText pins the text rendering: the
// usual summary line, then one line per withdrawn entry with its platform.
func TestRepoRemoveVersionListsEveryPlatformInText(t *testing.T) {
	mPath, keyDir, env := setupHelloBuilds(t,
		helloBuild{"a", "1.0.0", "linux/amd64"},
		helloBuild{"b", "1.0.0", "darwin/arm64"},
		helloBuild{"c", "2.0.0", ""})

	out, err := runRepo(t, env, "repo", "remove", "hello@1.0.0", "--manifest", mPath, "--key-dir", keyDir)
	if err != nil {
		t.Fatalf("repo remove: %v (out=%s)", err, out)
	}
	want := regexp.MustCompile(`\ARemoved hello@1\.0\.0 and rebuilt the repository \(serial \d+\)\n` +
		`  pkgs/a \(linux/amd64\)\n  pkgs/b \(darwin/arm64\)\n\z`)
	if !want.MatchString(out) {
		t.Fatalf("output = %q, want the summary line plus one line per platform", out)
	}
}

// TestRepoRemoveSingleEntryVersionUnchanged pins that a version published as
// one platform-agnostic entry keeps today's text output byte-for-byte, and
// that its JSON result only gains the removed list, as the additive JSON
// contract allows.
func TestRepoRemoveSingleEntryVersionUnchanged(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			mPath, keyDir, env := setupHelloBuilds(t,
				helloBuild{"d", "1.0.0", ""},
				helloBuild{"c", "2.0.0", ""})

			out, err := runRepo(t, env, "repo", "remove", "hello@1.0.0",
				"--manifest", mPath, "--key-dir", keyDir, "--format", format)
			if err != nil {
				t.Fatalf("repo remove: %v (out=%s)", err, out)
			}
			if format == "text" {
				want := regexp.MustCompile(`\ARemoved hello@1\.0\.0 and rebuilt the repository \(serial \d+\)\n\z`)
				if !want.MatchString(out) {
					t.Fatalf("output = %q, want exactly the one-line summary", out)
				}
			} else {
				var res repoRemoveJSON
				if err := json.Unmarshal([]byte(out), &res); err != nil {
					t.Fatalf("decode %q: %v", out, err)
				}
				want := []removedJSON{{"pkgs/d", "any"}}
				if res.Status != "ok" || res.Data.Package != "hello" || res.Data.Version != "1.0.0" ||
					res.Data.Serial == 0 || !slices.Equal(res.Data.Removed, want) {
					t.Fatalf("result = %+v, want hello@1.0.0 with removed %+v", res, want)
				}
			}
			if got := manifestHelloSources(t, mPath); !slices.Equal(got, []string{"pkgs/c"}) {
				t.Fatalf("manifest hello sources = %v, want [pkgs/c]", got)
			}
			if got := publishedHelloVersions(t, mPath); !slices.Equal(got, []string{"2.0.0"}) {
				t.Fatalf("published hello versions = %v, want [2.0.0]", got)
			}
		})
	}
}

// TestRepoRemoveUnknownVersionErrorsAndLeavesManifest pins that a version no
// entry builds fails exactly as before — same message, every published version
// listed once — and writes nothing.
func TestRepoRemoveUnknownVersionErrorsAndLeavesManifest(t *testing.T) {
	mPath, keyDir, env := setupHelloBuilds(t,
		helloBuild{"a", "1.0.0", "linux/amd64"},
		helloBuild{"b", "1.0.0", "darwin/arm64"},
		helloBuild{"c", "2.0.0", ""})
	before := readManifestBytes(t, mPath)

	_, err := runRepo(t, env, "repo", "remove", "hello@9.9.9", "--manifest", mPath, "--key-dir", keyDir)
	var ce *CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("repo remove hello@9.9.9 = %v (%T), want *CLIError", err, err)
	}
	if ce.Msg != "package hello has no published version 9.9.9" {
		t.Fatalf("Msg = %q", ce.Msg)
	}
	if ce.Hint != "published versions of hello: 1.0.0, 2.0.0" {
		t.Fatalf("Hint = %q, want each published version listed once", ce.Hint)
	}
	if !bytes.Equal(readManifestBytes(t, mPath), before) {
		t.Fatal("a failed repo remove modified polypkg-repo.yaml")
	}
}

// TestRepoRemoveVersionNamesUnreadableEntry pins that an entry whose version
// cannot be read blocks `@<version>` (every entry must be read to find all of
// a version's builds) with an error that says so and names the entry to fix,
// and that nothing is written.
func TestRepoRemoveVersionNamesUnreadableEntry(t *testing.T) {
	mPath, keyDir, env := setupHelloBuilds(t,
		helloBuild{"a", "1.0.0", "linux/amd64"},
		helloBuild{"b", "2.0.0", ""})
	if err := os.Remove(filepath.Join(filepath.Dir(mPath), "pkgs", "b", "polypkg.yaml")); err != nil {
		t.Fatal(err)
	}
	before := readManifestBytes(t, mPath)

	_, err := runRepo(t, env, "repo", "remove", "hello@1.0.0", "--manifest", mPath, "--key-dir", keyDir)
	var ce *CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("repo remove hello@1.0.0 = %v (%T), want *CLIError", err, err)
	}
	for _, want := range []string{"hello@1.0.0", "every entry of hello must be readable"} {
		if !strings.Contains(ce.Msg, want) {
			t.Fatalf("Msg %q does not mention %q", ce.Msg, want)
		}
	}
	for _, want := range []string{"pkgs/b", "polypkg-repo.yaml"} {
		if !strings.Contains(ce.Hint, want) {
			t.Fatalf("Hint %q does not mention %q", ce.Hint, want)
		}
	}
	if !bytes.Equal(readManifestBytes(t, mPath), before) {
		t.Fatal("a failed repo remove modified polypkg-repo.yaml")
	}
}

// repo add and repo remove rebuild the repository, so a trust-bundle change
// they publish is shown the same way repo build shows it, never silently.
func TestRepoAddAndRemoveShowTheTrustBundleChange(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")
	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}
	pkgDir := writeHelloPkgSource(t, repoDir)

	fixture, err := os.ReadFile(filepath.Join("..", "repo", "testdata", "sigstore-public-good-trusted-root.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "trusted_root.json"), fixture, 0o644); err != nil {
		t.Fatal(err)
	}
	const rootsEntry = "sigstore_roots:\n    - ./trusted_root.json\n"
	before := readManifestBytes(t, mPath)
	if err := os.WriteFile(mPath, append(slices.Clone(before), rootsEntry...), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runRepo(t, env, "repo", "add", pkgDir, "--manifest", mPath, "--key-dir", keyDir)
	if err != nil {
		t.Fatalf("repo add: %v (out=%s)", err, out)
	}
	for _, want := range []string{
		"The trust bundle now vouches for:",
		"sigstore root: Fulcio root sha256:3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1, valid 2022-04-13T20:06:15Z to open-ended",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("repo add output lacks %q:\n%s", want, out)
		}
	}

	// Drop sigstore_roots again: the remove's rebuild withdraws the bundle.
	withRoots := readManifestBytes(t, mPath)
	if !bytes.Contains(withRoots, []byte(rootsEntry)) {
		t.Fatalf("repo add rewrote the sigstore_roots entry; the test cannot drop it:\n%s", withRoots)
	}
	if err := os.WriteFile(mPath, bytes.Replace(withRoots, []byte(rootsEntry), nil, 1), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = runRepo(t, env, "--format", "json", "repo", "remove", "hello", "--manifest", mPath, "--key-dir", keyDir)
	if err != nil {
		t.Fatalf("repo remove: %v (out=%s)", err, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	res, err := schema.ParseCLIResult(strings.NewReader(lines[len(lines)-1]))
	if err != nil {
		t.Fatalf("parse result: %v (out=%s)", err, out)
	}
	if tb, _ := res.Data["trust_bundle"].(map[string]any); tb["withdrawn"] != true {
		t.Fatalf("data.trust_bundle = %v, want the withdrawal", res.Data["trust_bundle"])
	}

	// A rebuild that leaves the bundle alone does not report it.
	out, err = runRepo(t, env, "--format", "json", "repo", "add", pkgDir, "--manifest", mPath, "--key-dir", keyDir)
	if err != nil {
		t.Fatalf("second repo add: %v (out=%s)", err, out)
	}
	if strings.Contains(out, "trust_bundle") {
		t.Fatalf("a repo add that leaves the trust bundle alone reported it: %s", out)
	}
}

// makeSetuidContent sets setuid on dir's content/bin/hello and returns that
// file's source-relative path. It skips t when the filesystem drops the bit.
func makeSetuidContent(t testing.TB, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "content", "bin", "hello")
	if err := os.Chmod(bin, 0o755|fs.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(bin); err != nil {
		t.Fatal(err)
	} else if info.Mode()&fs.ModeSetuid == 0 {
		t.Skipf("this filesystem does not keep setuid (got %v)", info.Mode())
	}
	return "content/bin/hello"
}

// makeTooDeepContent writes a content file one path segment deeper than any
// install could extract and returns its source-relative path.
func makeTooDeepContent(t testing.TB, dir string) string {
	t.Helper()
	// "content", then the nested directories, then the file.
	segs := append([]string{"content"}, slices.Repeat([]string{"d"}, archive.MaxMemberDepth-1)...)
	if err := os.MkdirAll(filepath.Join(append([]string{dir}, segs...)...), 0o755); err != nil {
		t.Fatal(err)
	}
	rel := path.Join(append(segs, "f")...)
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), []byte("deep"), 0o644); err != nil {
		t.Fatal(err)
	}
	return rel
}

// TestRepoAddNamesTheFileThatCannotBePacked pins that a pack refusal reaches
// the user with the offending file, the reason, and what to change, instead
// of only "cannot pack package".
func TestRepoAddNamesTheFileThatCannotBePacked(t *testing.T) {
	for _, tc := range []struct {
		name     string
		make     func(testing.TB, string) string
		reason   string
		wantHint string
	}{
		{"setuid", makeSetuidContent, "is setuid", "chmod u-s,g-s,-t"},
		{"too deep", makeTooDeepContent, "more than 64 path segments", "shorten"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sandboxUserEnv(t)
			repoDir := filepath.Join(t.TempDir(), "r")
			keyDir := t.TempDir()
			env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
			if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
				t.Fatalf("init: %v", err)
			}
			src := writeHelloPkgSource(t, repoDir)
			rel := tc.make(t, src)
			_, err := runRepo(t, env, "repo", "add", src,
				"--manifest", filepath.Join(repoDir, "polypkg-repo.yaml"), "--key-dir", keyDir)
			var ce *CLIError
			if !errors.As(err, &ce) {
				t.Fatalf("repo add = %v (%T), want a CLIError", err, err)
			}
			for _, want := range []string{`cannot pack package "hello"`, fmt.Sprintf("%q", rel), tc.reason} {
				if !strings.Contains(ce.Msg, want) {
					t.Errorf("Msg = %q, want it to contain %q", ce.Msg, want)
				}
			}
			if !strings.Contains(ce.Hint, tc.wantHint) {
				t.Errorf("Hint = %q, want it to contain %q", ce.Hint, tc.wantHint)
			}
		})
	}
}
