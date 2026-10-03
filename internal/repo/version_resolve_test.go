package repo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// TestEntryVersionReadsSourceTree covers the cheap branch: a source entry's
// version is one YAML read away.
func TestEntryVersionReadsSourceTree(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkgs", "hello")
	if err := os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "schema: polypkg.package/v1\nname: hello\nversion: 2.3.4\nactions: []\n"
	if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := EntryVersion(root, schema.RepoPackage{Source: "./pkgs/hello"})
	if err != nil {
		t.Fatalf("EntryVersion: %v", err)
	}
	if got != "2.3.4" {
		t.Fatalf("EntryVersion = %q, want 2.3.4", got)
	}
}

// TestEntryVersionExtractsPrebuiltArtifact covers the expensive branch: a
// prebuilt entry has its version read out of the artifact itself, by
// extracting it (the version lives inside the artifact, not in the manifest).
func TestEntryVersionExtractsPrebuiltArtifact(t *testing.T) {
	root := t.TempDir()
	srcDir := filepath.Join(root, "origin", "hello")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writePkgSrc(t, srcDir) // polypkg.yaml (hello 1.0.0) + content/bin/hello
	artifact, _, err := PackArtifact(srcDir)
	if err != nil {
		t.Fatalf("PackArtifact: %v", err)
	}
	artPath := filepath.Join(root, "hello.tar.zst")
	if err := os.WriteFile(artPath, artifact, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := EntryVersion(root, schema.RepoPackage{Prebuilt: &schema.RepoPrebuilt{Artifact: "hello.tar.zst"}})
	if err != nil {
		t.Fatalf("EntryVersion: %v", err)
	}
	if got != "1.0.0" {
		t.Fatalf("EntryVersion = %q, want 1.0.0", got)
	}
}
