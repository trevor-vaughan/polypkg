package cli

import (
	"archive/tar"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tarHasEntry(t *testing.T, path, want string) bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return false
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		if hdr.Name == want {
			return true
		}
	}
}

// buildHelloRepo initialises and builds a repository publishing hello and
// returns its manifest path and key directory.
func buildHelloRepo(t *testing.T) (mPath, keyDir string) {
	t.Helper()
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir = t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath = filepath.Join(repoDir, "polypkg-repo.yaml")

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
	return mPath, keyDir
}

func TestRepoExportBundleWritesSignedTarball(t *testing.T) {
	sandboxUserEnv(t)
	mPath, keyDir := buildHelloRepo(t)
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}

	bundle := filepath.Join(t.TempDir(), "bundle.tar")
	if _, err := runRepo(t, env, "repo", "export-bundle", "--manifest", mPath, "--key-dir", keyDir, "-o", bundle); err != nil {
		t.Fatalf("export-bundle: %v", err)
	}
	if _, err := os.Stat(bundle); err != nil {
		t.Fatalf("bundle not written: %v", err)
	}
	if !tarHasEntry(t, bundle, "pool-manifest.json") {
		t.Fatal("bundle missing pool-manifest.json")
	}
	if !tarHasEntry(t, bundle, "index.json") {
		t.Fatal("bundle missing index.json")
	}
}

func TestRepoExportBundleNamesAMissingOutputDirectory(t *testing.T) {
	sandboxUserEnv(t)
	mPath, keyDir := buildHelloRepo(t)
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	missing := filepath.Join(t.TempDir(), "nope")
	bundle := filepath.Join(missing, "bundle.tar")

	_, err := runRepo(t, env, "repo", "export-bundle", "--manifest", mPath, "--key-dir", keyDir, "-o", bundle)
	var ce *CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("want CLIError, got %T: %v", err, err)
	}
	if want := "cannot write bundle " + bundle + ": directory " + missing + " does not exist"; ce.Msg != want {
		t.Fatalf("Msg = %q, want %q", ce.Msg, want)
	}
	if !strings.Contains(ce.Hint, "-o") {
		t.Fatalf("Hint = %q, want it to mention -o", ce.Hint)
	}
}
