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
	add, err := PlanAddPackage(mPath, "hello", "./pkgs/hello")
	if err != nil {
		t.Fatalf("PlanAddPackage: %v", err)
	}
	if err := add.Commit(); err != nil {
		t.Fatalf("commit add: %v", err)
	}
	m := mustParseManifest(t, mPath)
	if m.Packages["hello"].Source != "./pkgs/hello" {
		t.Fatalf("hello not added: %+v", m.Packages)
	}
	rm, err := PlanRemovePackage(mPath, "hello")
	if err != nil {
		t.Fatalf("PlanRemovePackage: %v", err)
	}
	if err := rm.Commit(); err != nil {
		t.Fatalf("commit remove: %v", err)
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
	if _, err := PlanRemovePackage(mPath, "ghost"); err == nil {
		t.Fatal("expected error removing unknown package")
	}
}

// TestPlanEditLeavesManifestUntouchedUntilCommit is the unit-level statement of
// the add/remove invariant: planning an edit must not write anything, so a
// caller that fails between planning and committing leaves the file alone.
func TestPlanEditLeavesManifestUntouchedUntilCommit(t *testing.T) {
	dir := t.TempDir()
	mPath := filepath.Join(dir, "polypkg-repo.yaml")
	base := "schema: polypkg.repo/v1\nsource: example\noutput: ./public\nkey:\n  path: k.key\n  kdf: scrypt\npackages:\n  hello:\n    source: ./pkgs/hello\n"
	if err := os.WriteFile(mPath, []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}

	add, err := PlanAddPackage(mPath, "goodbye", "./pkgs/goodbye")
	if err != nil {
		t.Fatal(err)
	}
	rm, err := PlanRemovePackage(mPath, "hello")
	if err != nil {
		t.Fatal(err)
	}
	// The planned manifests carry the edits...
	if _, ok := add.Manifest.Packages["goodbye"]; !ok {
		t.Fatal("planned add does not carry goodbye")
	}
	if _, ok := rm.Manifest.Packages["hello"]; ok {
		t.Fatal("planned remove still carries hello")
	}
	// ...while the file on disk carries neither.
	raw, err := os.ReadFile(mPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != base {
		t.Fatalf("planning rewrote the manifest\nbefore:\n%s\nafter:\n%s", base, raw)
	}

	if err := add.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, ok := mustParseManifest(t, mPath).Packages["goodbye"]; !ok {
		t.Fatal("commit did not persist the add")
	}
}

func TestCommitAddPersistsValidManifest(t *testing.T) {
	dir := t.TempDir()
	mPath := filepath.Join(dir, "polypkg-repo.yaml")
	_ = os.WriteFile(mPath, []byte("schema: polypkg.repo/v1\nsource: e\noutput: ./public\nkey:\n  path: k\n  kdf: scrypt\npackages: {}\n"), 0o644)
	add, err := PlanAddPackage(mPath, "a", "./a")
	if err != nil {
		t.Fatal(err)
	}
	if err := add.Commit(); err != nil {
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
