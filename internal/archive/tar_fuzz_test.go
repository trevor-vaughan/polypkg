package archive

import (
	"archive/tar"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// FuzzExtractTar feeds arbitrary (mutated) tar bytes to ExtractTar under
// PolicyPackage, extracting into an empty root beside an empty sibling.
// Whatever the bytes, it must not panic and must not create anything outside
// the root. When extraction succeeds, Placed must describe the resulting tree
// exactly: every path is reported once, every reported path exists with the
// reported kind, and every path in the tree is reported.
//
// Run the seed corpus as a normal test:   go test ./internal/archive/
// Run the mutating fuzzer:                 task fuzz FUZZTARGET=FuzzExtractTar FUZZPKG=./internal/archive/
func FuzzExtractTar(f *testing.F) {
	for _, s := range extractFuzzSeeds() {
		f.Add(s)
	}

	// Small limits keep each iteration cheap; the invariants under test are
	// independent of the caps.
	opts := Options{
		Policy:  PolicyPackage,
		Limits:  Limits{MaxFileBytes: 4 << 10, MaxTotalBytes: 64 << 10, MaxEntries: 256},
		DirPerm: 0o700,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		base := t.TempDir()
		dir := filepath.Join(base, "root")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(base, "outside"), 0o700); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()

		// Must never panic, whatever the bytes. Errors are expected and fine.
		placed, extractErr := ExtractTar(bytes.NewReader(data), root, opts)

		// Nothing outside the root: base holds only root and an empty outside.
		ents, err := os.ReadDir(base)
		if err != nil {
			t.Fatalf("read base: %v", err)
		}
		for _, e := range ents {
			if e.Name() != "root" && e.Name() != "outside" {
				t.Fatalf("extraction escaped the root: created %q beside it", e.Name())
			}
		}
		if outside, err := os.ReadDir(filepath.Join(base, "outside")); err != nil || len(outside) != 0 {
			t.Fatalf("extraction wrote outside the root: %v entries, err %v", len(outside), err)
		}

		if extractErr != nil {
			if placed != nil {
				t.Fatalf("failed extraction returned a non-nil Placed: %v", placed)
			}
			return
		}

		// Every Placed path is unique and exists with the reported kind.
		reported := make(map[string]bool, len(placed))
		for _, p := range placed {
			if reported[p.Path] {
				t.Fatalf("path %q reported twice", p.Path)
			}
			reported[p.Path] = true
			info, err := root.Lstat(filepath.FromSlash(p.Path))
			if err != nil {
				t.Fatalf("reported path %q: %v", p.Path, err)
			}
			if got := kindOf(info.Mode()); got != p.Kind {
				t.Fatalf("reported path %q as %q, but it is %q", p.Path, p.Kind, got)
			}
		}

		// Every path in the tree is reported. WalkDir does not follow
		// symlinks, so this sees exactly what lies under the root.
		err = filepath.WalkDir(dir, func(p string, _ fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			if rel != "." && !reported[filepath.ToSlash(rel)] {
				t.Fatalf("%q is in the tree but not in Placed", rel)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk root: %v", err)
		}
	})
}

// kindOf maps a file mode to the Placed.Kind it should be reported as.
func kindOf(m fs.FileMode) string {
	switch {
	case m.IsDir():
		return "dir"
	case m&fs.ModeSymlink != 0:
		return "symlink"
	case m.IsRegular():
		return "file"
	default:
		return m.Type().String()
	}
}

// extractFuzzSeeds are the hostile and ordinary tar shapes the fuzzer starts
// from, the same shapes internal/source seeds FuzzExtractTarZst with.
func extractFuzzSeeds() [][]byte {
	return [][]byte{
		tarOf(member{name: "polypkg.yaml", typeflag: tar.TypeReg, body: "schema: polypkg.package/v1\n", mode: 0o644}),
		tarOf(member{name: "dir/sub/file", typeflag: tar.TypeReg, body: "hi", mode: 0o644}),
		tarOf(member{name: "../escape", typeflag: tar.TypeReg, body: "x", mode: 0o644}),
		tarOf(member{name: "/abs", typeflag: tar.TypeReg, body: "x", mode: 0o644}),
		tarOf(member{name: "abslink", typeflag: tar.TypeSymlink, linkname: "/etc", mode: 0o644}),
		tarOf(member{name: "rellink", typeflag: tar.TypeSymlink, linkname: "../../../../etc", mode: 0o644}),
		tarOf(
			member{name: "target", typeflag: tar.TypeReg, body: "hi", mode: 0o644},
			member{name: "link", typeflag: tar.TypeSymlink, linkname: "target", mode: 0o644},
		),
		tarOf(
			member{name: "evil", typeflag: tar.TypeSymlink, linkname: "..", mode: 0o644},
			member{name: "evil/x", typeflag: tar.TypeReg, body: "x", mode: 0o644},
		),
		tarOf(member{name: "dev", typeflag: tar.TypeChar, mode: 0o644}),
	}
}
