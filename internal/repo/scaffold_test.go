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

// TestInitRepoKeepsKeyInsideKeyDir covers the defense-in-depth guard at the
// path-interpolation site: even when a caller bypasses the CLI/manifest
// validation and hands InitRepo a traversal-shaped source, the signing key
// still lands inside KeyDir.
func TestInitRepoKeepsKeyInsideKeyDir(t *testing.T) {
	for _, src := range []string{"../../evilsrc", "a/b", "..", "."} {
		t.Run(src, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "repo", "r")
			keyDir := filepath.Join(base, "repo", "keys", "a", "b")
			res, err := InitRepo(InitOptions{Dir: dir, KeyDir: keyDir, Source: src, Password: "pw", KDF: KDFScrypt})
			if err != nil {
				t.Fatalf("InitRepo: %v", err)
			}
			if got := filepath.Dir(res.KeyPath); got != keyDir {
				t.Fatalf("signing key escaped KeyDir: %s (parent %s, want %s)", res.KeyPath, got, keyDir)
			}
			if _, serr := os.Stat(res.KeyPath); serr != nil {
				t.Fatalf("key not written at %s: %v", res.KeyPath, serr)
			}
		})
	}
}

// TestInitRepoRecordsResolvableKeyPath covers a relative --key-dir.
//
// InitRepo creates the signing key at filepath.Join(KeyDir, <source>.key),
// which for a relative KeyDir lands relative to the process working directory.
// It used to record that same string in the manifest, but manifest paths are
// resolved against the MANIFEST directory, so `repo init ./myrepo --key-dir
// ./keys` wrote the key to ./keys/demo.key while every later command looked for
// ./myrepo/keys/demo.key:
//
//	error: signing key file not found at myrepo/keys/demo.key
//
// The path recorded in the manifest must name the file InitRepo actually wrote,
// whichever form KeyDir arrived in.
func TestInitRepoRecordsResolvableKeyPath(t *testing.T) {
	t.Chdir(t.TempDir())

	res, err := InitRepo(InitOptions{
		Dir: "myrepo", KeyDir: "keys", Source: "demo",
		Password: "pw", KDF: KDFScrypt,
	})
	if err != nil {
		t.Fatalf("InitRepo: %v", err)
	}

	m, err := loadManifestForEdit(res.ManifestPath)
	if err != nil {
		t.Fatalf("loadManifestForEdit: %v", err)
	}

	// Exactly how build.go reaches the key.
	resolved := resolveRel(filepath.Dir(res.ManifestPath), m.Key.Path)
	if _, err := os.Stat(resolved); err != nil {
		t.Fatalf("manifest key path %q resolves to %q, which does not exist: %v\n"+
			"InitRepo wrote the key to %q", m.Key.Path, resolved, err, res.KeyPath)
	}
}
