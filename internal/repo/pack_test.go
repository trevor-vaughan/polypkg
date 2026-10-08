package repo

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
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
	if !strings.Contains(err.Error(), `"content/link.txt" is not a regular file`) || strings.Contains(err.Error(), "content/content/") {
		t.Fatalf("error = %q, want it to name content/link.txt once", err)
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

// TestPackArtifactRefusesAMemberTooDeepToExtract pins that PackArtifact
// refuses a member name extraction would refuse, at the same bound: a member
// at exactly archive.MaxMemberDepth path segments packs, one deeper does not.
func TestPackArtifactRefusesAMemberTooDeepToExtract(t *testing.T) {
	for _, tc := range []struct {
		segments int
		wantErr  bool
	}{{archive.MaxMemberDepth, false}, {archive.MaxMemberDepth + 1, true}} {
		dir := t.TempDir()
		writePkgSrc(t, dir)
		// "content", then the nested directories, then the file.
		parent := filepath.Join(append([]string{dir, "content"}, slices.Repeat([]string{"d"}, tc.segments-2)...)...)
		if err := os.MkdirAll(parent, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(parent, "f"), []byte("deep"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, _, err := PackArtifact(dir)
		if !tc.wantErr {
			if err != nil {
				t.Fatalf("%d segments: PackArtifact = %v, want success", tc.segments, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "more than 64 path segments") {
			t.Fatalf("%d segments: PackArtifact = %v, want the depth refusal", tc.segments, err)
		}
	}
}

// TestPackArtifactRefusesANonUTF8Name pins that PackArtifact refuses a
// content file whose name is not valid UTF-8, as extraction does, and names
// the file in a PackRefusal.
func TestPackArtifactRefusesANonUTF8Name(t *testing.T) {
	for _, name := range []string{"\x80\xffg", "a\x9bb"} {
		dir := t.TempDir()
		writePkgSrc(t, dir)
		if err := os.WriteFile(filepath.Join(dir, "content", name), []byte("x"), 0o644); err != nil {
			if errors.Is(err, syscall.EILSEQ) {
				t.Skipf("this filesystem refuses non-UTF-8 names: %v", err)
			}
			t.Fatal(err)
		}
		_, _, err := PackArtifact(dir)
		var refusal *PackRefusal
		if !errors.As(err, &refusal) {
			t.Fatalf("%q: PackArtifact = %v, want a *PackRefusal", name, err)
		}
		for _, want := range []string{fmt.Sprintf("%q is not valid UTF-8", "content/"+name), "rename"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%q: error %q does not mention %q", name, err, want)
			}
		}
	}
}

// TestExtractedEntriesCountsImplicitParents pins the count PackArtifact holds
// against the extraction entry limit: each member plus each distinct parent
// directory, since extraction counts the directories it creates.
func TestExtractedEntriesCountsImplicitParents(t *testing.T) {
	names := []string{"content/bin/a", "content/bin/b", "content/lib/x/y", "polypkg.yaml"}
	// Four members, plus content, content/bin, content/lib and content/lib/x.
	if got := extractedEntries(names); got != 8 {
		t.Fatalf("extractedEntries(%q) = %d, want 8", names, got)
	}
	if got := extractedEntries([]string{"polypkg.yaml"}); got != 1 {
		t.Fatalf("extractedEntries([polypkg.yaml]) = %d, want 1", got)
	}
}

// TestPackArtifactRefusesSpecialModeBits pins that a content file carrying
// setuid, setgid or sticky fails the build with the bits named, instead of
// being packed without them.
func TestPackArtifactRefusesSpecialModeBits(t *testing.T) {
	for _, tc := range []struct {
		mode fs.FileMode
		want string
	}{
		{0o755 | fs.ModeSetuid, `"content/bin/hello" is setuid;`},
		{0o755 | fs.ModeSetgid, `"content/bin/hello" is setgid;`},
		{0o755 | fs.ModeSticky, `"content/bin/hello" is sticky;`},
		{0o755 | fs.ModeSetuid | fs.ModeSetgid, `"content/bin/hello" is setuid and setgid;`},
	} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			dir := t.TempDir()
			writePkgSrc(t, dir)
			bin := filepath.Join(dir, "content", "bin", "hello")
			if err := os.Chmod(bin, tc.mode); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(bin)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode() != tc.mode {
				t.Skipf("this filesystem does not keep mode %v (got %v)", tc.mode, info.Mode())
			}
			_, _, err = PackArtifact(dir)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "chmod u-s,g-s,-t") {
				t.Fatalf("PackArtifact = %v, want a refusal containing %q", err, tc.want)
			}
		})
	}
}
