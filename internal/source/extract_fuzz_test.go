package source

import (
	"archive/tar"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzExtractTarZst feeds arbitrary (mutated) tar bytes to the extractor and
// asserts the two invariants that must hold for any input: it never panics, and
// it never creates or modifies anything outside the destination — no "../"
// escape into the parent, and no symlink inside dest that resolves outside it.
//
// It targets extractTar (the os.Root-confined extraction logic) on raw,
// uncompressed tar bytes rather than the zstd layer: the mutator can then craft
// hostile tar headers directly instead of wasting effort on zstd framing, and
// each iteration skips the decompressor. Seeds are the hostile shapes the
// extractor must resist, giving the mutator structured starting points.
//
// Run the seed corpus as a normal test:   go test ./internal/source/
// Run the mutating fuzzer:                 task fuzz   (go test -fuzz=FuzzExtractTarZst)
func FuzzExtractTarZst(f *testing.F) {
	seeds := [][]byte{
		buildTar(tarEntry{name: "polypkg.yaml", typeflag: tar.TypeReg, body: []byte("schema: polypkg.package/v1\n")}),
		buildTar(tarEntry{name: "dir/sub/file", typeflag: tar.TypeReg, body: []byte("hi")}),
		buildTar(tarEntry{name: "../escape", typeflag: tar.TypeReg, body: []byte("x")}),
		buildTar(tarEntry{name: "/abs", typeflag: tar.TypeReg, body: []byte("x")}),
		buildTar(tarEntry{name: "abslink", typeflag: tar.TypeSymlink, linkname: "/etc"}),
		buildTar(tarEntry{name: "rellink", typeflag: tar.TypeSymlink, linkname: "../../../../etc"}),
		buildTar(
			tarEntry{name: "target", typeflag: tar.TypeReg, body: []byte("hi")},
			tarEntry{name: "link", typeflag: tar.TypeSymlink, linkname: "target"},
		),
		buildTar(
			tarEntry{name: "evil", typeflag: tar.TypeSymlink, linkname: ".."},
			tarEntry{name: "evil/x", typeflag: tar.TypeReg, body: []byte("x")},
		),
		buildTar(tarEntry{name: "dev", typeflag: tar.TypeChar}),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	// Small limits keep each iteration cheap; the path-confinement logic under
	// test is independent of the caps.
	lim := extractLimits{maxFileBytes: 4 << 10, maxTotalBytes: 64 << 10, maxEntries: 256}

	f.Fuzz(func(t *testing.T, data []byte) {
		base := t.TempDir()
		dest := filepath.Join(base, "dest")

		// Must never panic, whatever the bytes. Errors are expected and fine.
		_ = extractTar(bytes.NewReader(data), dest, lim)

		// Containment 1: nothing escaped into the parent of dest.
		parent, err := os.ReadDir(base)
		if err != nil {
			t.Fatalf("read base: %v", err)
		}
		for _, e := range parent {
			if e.Name() != "dest" {
				t.Fatalf("extraction escaped into parent: created %q outside dest", e.Name())
			}
		}

		// Containment 2: no symlink inside dest may resolve outside dest.
		_ = filepath.WalkDir(dest, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d.Type()&fs.ModeSymlink == 0 {
				return nil
			}
			target, err := os.Readlink(p)
			if err != nil {
				return nil
			}
			resolved := target
			if !filepath.IsAbs(resolved) {
				resolved = filepath.Join(filepath.Dir(p), resolved)
			}
			rel, err := filepath.Rel(dest, filepath.Clean(resolved))
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Fatalf("extraction created a symlink escaping dest: %s -> %s", p, target)
			}
			return nil
		})
	})
}
