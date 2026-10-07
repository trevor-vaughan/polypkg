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

	got, plat, err := EntryVersion(root, schema.RepoPackage{Source: "./pkgs/hello"})
	if err != nil {
		t.Fatalf("EntryVersion: %v", err)
	}
	if got != "2.3.4" || plat != "" {
		t.Fatalf("EntryVersion = %q, %q; want 2.3.4 and no platform", got, plat)
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

	got, plat, err := EntryVersion(root, schema.RepoPackage{Prebuilt: &schema.RepoPrebuilt{Artifact: "hello.tar.zst"}})
	if err != nil {
		t.Fatalf("EntryVersion: %v", err)
	}
	if got != "1.0.0" || plat != "" {
		t.Fatalf("EntryVersion = %q, %q; want 1.0.0 and no platform", got, plat)
	}
}

// TestEntryVersionReportsPlatform pins that both entry kinds report the
// platform their polypkg.yaml declares — the source tree's, or the one inside
// a prebuilt artifact — so `repo remove name@version` can name what it withdraws.
func TestEntryVersionReportsPlatform(t *testing.T) {
	root := t.TempDir()
	writePlatformPkgSrc(t, filepath.Join(root, "pkgs", "a"), "linux/amd64", "a")
	_, plat, err := EntryVersion(root, schema.RepoPackage{Source: "./pkgs/a"})
	if err != nil {
		t.Fatalf("EntryVersion(source): %v", err)
	}
	if plat != "linux/amd64" {
		t.Fatalf("source platform = %q, want linux/amd64", plat)
	}

	srcDir := filepath.Join(root, "origin", "b")
	writePlatformPkgSrc(t, srcDir, "darwin/arm64", "b")
	artifact, _, err := PackArtifact(srcDir)
	if err != nil {
		t.Fatalf("PackArtifact: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.tar.zst"), artifact, 0o644); err != nil {
		t.Fatal(err)
	}
	_, plat, err = EntryVersion(root, schema.RepoPackage{Prebuilt: &schema.RepoPrebuilt{Artifact: "b.tar.zst"}})
	if err != nil {
		t.Fatalf("EntryVersion(prebuilt): %v", err)
	}
	if plat != "darwin/arm64" {
		t.Fatalf("prebuilt platform = %q, want darwin/arm64", plat)
	}
}
