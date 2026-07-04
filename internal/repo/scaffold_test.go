package repo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitRepoScaffolds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "myrepo")
	keyDir := t.TempDir()
	res, err := InitRepo(InitOptions{Dir: dir, KeyDir: keyDir, Source: "example", Password: "pw", KDF: KDFScrypt})
	if err != nil {
		t.Fatalf("InitRepo: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "polypkg-repo.yaml")); err != nil {
		t.Fatalf("manifest not written: %v", err)
	}
	if _, err := os.Stat(res.KeyPath); err != nil {
		t.Fatalf("key not written: %v", err)
	}
	if _, err := LoadKey(res.KeyPath, "pw"); err != nil {
		t.Fatalf("generated key does not load: %v", err)
	}
	if res.TrustRootPath == "" {
		t.Fatal("TrustRootPath must be non-empty")
	}
	if _, err := os.Stat(res.TrustRootPath); err != nil {
		t.Fatalf("trust_root.pub not written at %s: %v", res.TrustRootPath, err)
	}
	// The written manifest must parse + validate.
	mustParseManifest(t, res.ManifestPath) // helper from manifest_edit_test.go (same package)
}

func TestInitRepoRefusesExistingManifest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "myrepo")
	keyDir := t.TempDir()
	opts := InitOptions{Dir: dir, KeyDir: keyDir, Source: "example", Password: "pw", KDF: KDFScrypt}
	if _, err := InitRepo(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := InitRepo(opts); err == nil {
		t.Fatal("expected error re-initializing over an existing manifest")
	}
}

func TestInitRepoRefusesKeyDirInsideOutput(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "myrepo")
	keyDir := filepath.Join(dir, "public", "keys") // inside output
	if _, err := InitRepo(InitOptions{Dir: dir, KeyDir: keyDir, Source: "example", Password: "pw", KDF: KDFScrypt}); err == nil {
		t.Fatal("expected error: key dir inside output")
	}
}
