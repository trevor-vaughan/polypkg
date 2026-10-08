package importer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPkgLintRendersFindings(t *testing.T) {
	dir := t.TempDir()
	recipe := `schema: polypkg.package/v1
name: tool
version: 1.0.0
actions:
  - phase: post-place
    action: install
    params:
      src: $PKG/content/missing
      dest: $ACTIVE/tool/bin/tool
`
	if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(recipe), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := PkgLint(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || !strings.HasPrefix(findings[0], "error PKG006 polypkg.yaml:") {
		t.Fatalf("findings = %q, want one PKG006 error with its line", findings)
	}
}

func TestPkgLintRefusesAMissingSource(t *testing.T) {
	if _, err := PkgLint(t.TempDir()); err == nil {
		t.Fatal("PkgLint of a directory without polypkg.yaml succeeded")
	}
}
