package archive_test

import (
	"bytes"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/archive"
)

// FuzzExtractArchive feeds arbitrary bytes through Detect and Extract under
// PolicyStrict and asserts what must hold for any input: no panic; nothing is
// written outside the root; and a successful extraction leaves exactly the
// reported entries, all regular files with mode 0o644 or 0o755, directories
// with DirPerm, or symlinks that resolve inside the root. Seeds hold one valid
// archive per format, so the mutator starts from real framing in each.
//
// Run the seed corpus as a normal test:   go test ./internal/archive/
// Run the mutating fuzzer:
//
//	task fuzz FUZZTARGET=FuzzExtractArchive FUZZPKG=./internal/archive/
func FuzzExtractArchive(f *testing.F) {
	seed := []fixtureMember{
		{name: "pkg/", kind: fixtureDir},
		{name: "pkg/bin/tool", kind: fixtureFile, mode: 0o755, body: "#!/bin/sh\necho tool\n"},
		{name: "pkg/README", kind: fixtureFile, body: "readme\n"},
		{name: "pkg/tool", kind: fixtureSymlink, target: "bin/tool"},
	}
	for _, format := range allFormats {
		f.Add(fixtureArchive(f, format, seed...))
	}

	// Small limits keep each iteration cheap; confinement does not depend on them.
	limits := archive.Limits{MaxFileBytes: 4 << 10, MaxTotalBytes: 64 << 10, MaxEntries: 256}

	f.Fuzz(func(t *testing.T, data []byte) {
		format, err := archive.Detect(data[:min(len(data), archive.DetectHeaderLen)])
		if err != nil {
			return
		}
		base, root := newTestRoot(t)
		opts := archive.Options{Format: format, Policy: archive.PolicyStrict, Limits: limits, DirPerm: 0o755}
		placed, err := archive.Extract(bytes.NewReader(data), int64(len(data)), root, opts)
		assertNothingOutside(t, base)
		if err != nil {
			return
		}
		if len(placed) > limits.MaxEntries {
			t.Fatalf("placed %d entries, more than MaxEntries %d", len(placed), limits.MaxEntries)
		}
		assertPlacedTree(t, root, placed)
		assertConfinedAndNormalised(t, filepath.Join(base, "dest"), placed)
	})
}

// assertConfinedAndNormalised checks every placed entry against the strict
// policy: normalised file modes, DirPerm directories (0o755 here), and
// symlinks that resolve inside dest on disk, not just lexically.
func assertConfinedAndNormalised(t *testing.T, dest string, placed []archive.Placed) {
	t.Helper()
	realDest, err := filepath.EvalSymlinks(dest)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range placed {
		switch p.Kind {
		case "file":
			if p.Mode != 0o644 && p.Mode != 0o755 {
				t.Fatalf("%s: file mode %v is not normalised", p.Path, p.Mode)
			}
		case "dir":
			if p.Mode != 0o755 {
				t.Fatalf("%s: directory mode %v, want DirPerm 0o755", p.Path, p.Mode)
			}
		case "symlink":
			resolved, err := filepath.EvalSymlinks(filepath.Join(dest, filepath.FromSlash(p.Path)))
			if err != nil {
				// Dangling or looping: nothing to follow, so check the target
				// lexically from the link's directory.
				lexical := path.Join(path.Dir(p.Path), p.Target)
				if path.IsAbs(p.Target) || lexical == ".." || strings.HasPrefix(lexical, "../") {
					t.Fatalf("%s -> %s escapes the root", p.Path, p.Target)
				}
				continue
			}
			rel, err := filepath.Rel(realDest, resolved)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Fatalf("%s -> %s resolves outside the root to %s", p.Path, p.Target, resolved)
			}
		default:
			t.Fatalf("%s: unexpected kind %q", p.Path, p.Kind)
		}
	}
}
