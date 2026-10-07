package repo

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/trevor-vaughan/polypkg/internal/archive"
)

func writePkgSrc(t *testing.T, dir string) {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"
	if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "content", "bin", "hello"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestPackArtifactReadsNameVersionAndIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	writePkgSrc(t, dir)

	a1, pkg, err := PackArtifact(dir)
	if err != nil {
		t.Fatalf("PackArtifact: %v", err)
	}
	if pkg.Name != "hello" || pkg.Version != "1.0.0" {
		t.Fatalf("name/version = %q/%q", pkg.Name, pkg.Version)
	}
	a2, _, err := PackArtifact(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a1, a2) {
		t.Fatal("PackArtifact is not deterministic")
	}
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	raw, err := dec.DecodeAll(a1, nil)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Contains(raw, []byte("polypkg.package/v1")) {
		t.Fatal("archive missing manifest")
	}
	if !bytes.Contains(raw, []byte("content/bin/hello")) {
		t.Fatal("archive missing content file path")
	}
}

func TestPackArtifactMissingManifestErrors(t *testing.T) {
	dir := t.TempDir() // no polypkg.yaml
	if _, _, err := PackArtifact(dir); err == nil {
		t.Fatal("expected error when polypkg.yaml is missing")
	}
}

func TestPackArtifactNoContentDir(t *testing.T) {
	dir := t.TempDir()
	manifest := "schema: polypkg.package/v1\nname: minimal\nversion: 0.1.0\nactions: []\n"
	if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	artifact, pkg, err := PackArtifact(dir)
	if err != nil {
		t.Fatalf("PackArtifact: %v", err)
	}
	if pkg.Name != "minimal" {
		t.Fatalf("name = %q, want minimal", pkg.Name)
	}
	if pkg.Version != "0.1.0" {
		t.Fatalf("version = %q, want 0.1.0", pkg.Version)
	}
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	raw, err := dec.DecodeAll(artifact, nil)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Contains(raw, []byte("polypkg.package/v1")) {
		t.Fatal("archive missing manifest schema marker")
	}
}

func TestPackArtifactRejectsSymlinkInContent(t *testing.T) {
	dir := t.TempDir()
	manifest := "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"
	if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "content"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "content", "real.txt")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "content", "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks not supported on this platform: %v", err)
	}

	_, _, err := PackArtifact(dir)
	if err == nil {
		t.Fatal("expected error for symlink in content/, got nil")
	}
}

func TestPackArtifactRefusesAMemberOverTheLimit(t *testing.T) {
	dir := t.TempDir()
	writePkgSrc(t, dir)
	big := filepath.Join(dir, "content", "big.tar.gz")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// Sparse: Truncate grows the file without writing 1 GiB.
	if err := os.Truncate(big, archive.DefaultLimits().MaxFileBytes+1); err != nil {
		t.Fatal(err)
	}
	_, _, err = PackArtifact(dir)
	if err == nil {
		t.Fatal("PackArtifact packed a member no install could unpack")
	}
	for _, want := range []string{"content/big.tar.gz", "1 GiB"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}
