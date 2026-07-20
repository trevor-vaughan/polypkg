package repo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func TestAddAndRemovePackage(t *testing.T) {
	dir := t.TempDir()
	mPath := filepath.Join(dir, "polypkg-repo.yaml")
	base := "schema: polypkg.repo/v1\nsource: example\noutput: ./public\nkey:\n  path: k.key\n  kdf: scrypt\npackages: {}\n"
	if err := os.WriteFile(mPath, []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AddPackage(mPath, "hello", "./pkgs/hello"); err != nil {
		t.Fatalf("AddPackage: %v", err)
	}
	m := mustParseManifest(t, mPath)
	if m.Packages["hello"].Source != "./pkgs/hello" {
		t.Fatalf("hello not added: %+v", m.Packages)
	}
	if err := RemovePackage(mPath, "hello"); err != nil {
		t.Fatalf("RemovePackage: %v", err)
	}
	m = mustParseManifest(t, mPath)
	if _, ok := m.Packages["hello"]; ok {
		t.Fatal("hello not removed")
	}
}

func TestRemoveUnknownPackageErrors(t *testing.T) {
	dir := t.TempDir()
	mPath := filepath.Join(dir, "polypkg-repo.yaml")
	_ = os.WriteFile(mPath, []byte("schema: polypkg.repo/v1\nsource: e\noutput: ./public\nkey:\n  path: k\n  kdf: scrypt\npackages: {}\n"), 0o644)
	if err := RemovePackage(mPath, "ghost"); err == nil {
		t.Fatal("expected error removing unknown package")
	}
}

func TestAddPackagePersistsValidManifest(t *testing.T) {
	dir := t.TempDir()
	mPath := filepath.Join(dir, "polypkg-repo.yaml")
	_ = os.WriteFile(mPath, []byte("schema: polypkg.repo/v1\nsource: e\noutput: ./public\nkey:\n  path: k\n  kdf: scrypt\npackages: {}\n"), 0o644)
	if err := AddPackage(mPath, "a", "./a"); err != nil {
		t.Fatal(err)
	}
	// Re-parsing must still pass schema validation (round-trip stays valid).
	mustParseManifest(t, mPath)
}

func mustParseManifest(t *testing.T, path string) *schema.RepoManifest {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := schema.ParseRepoManifest(f)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
