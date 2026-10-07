package source

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/archive"
)

// rawEntry is a tar member with an exact header mode; buildTar substitutes
// 0o644 for a zero mode, which hides the mode-0 shapes below.
type rawEntry struct {
	name, linkname, body string
	typeflag             byte
	mode                 int64
}

func rawTar(entries ...rawEntry) []byte {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: e.name, Linkname: e.linkname, Typeflag: e.typeflag,
			Mode: e.mode, Size: int64(len(e.body)),
		}); err != nil {
			panic(fmt.Sprintf("tar.WriteHeader: %v", err))
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			panic(fmt.Sprintf("tar.Write: %v", err))
		}
	}
	if err := tw.Close(); err != nil {
		panic(fmt.Sprintf("tar.Close: %v", err))
	}
	return raw.Bytes()
}

// The archive shapes where extraction and verification have diverged, or
// could: writes through or onto an in-archive symlink, modes that would leave
// an entry unreadable to its owner, duplicates, and implicit parents. Each
// declares whether extraction must accept it, so a refusal that is too broad
// fails the table instead of skipping the round trip.
// roundTripShape is an archive and whether extraction must accept it.
type roundTripShape struct {
	wantExtract bool
	data        []byte
}

var roundTripShapes = map[string]roundTripShape{
	"a file written through an in-archive symlink to a dir": {wantExtract: false, data: rawTar(
		rawEntry{name: "c/", typeflag: tar.TypeDir, mode: 0o755},
		rawEntry{name: "a", typeflag: tar.TypeSymlink, linkname: "c"},
		rawEntry{name: "a/b", typeflag: tar.TypeReg, body: "x", mode: 0o644},
	)},
	"a regular file over an earlier symlink": {wantExtract: false, data: rawTar(
		rawEntry{name: "t", typeflag: tar.TypeReg, body: "target", mode: 0o644},
		rawEntry{name: "l", typeflag: tar.TypeSymlink, linkname: "t"},
		rawEntry{name: "l", typeflag: tar.TypeReg, body: "over", mode: 0o644},
	)},
	"a write-only regular file": {wantExtract: true, data: rawTar(
		rawEntry{name: "w", typeflag: tar.TypeReg, body: "x", mode: 0o200},
	)},
	"a mode-0 regular file": {wantExtract: true, data: rawTar(
		rawEntry{name: "z", typeflag: tar.TypeReg, body: "x", mode: 0},
	)},
	"a mode-0 empty directory": {wantExtract: true, data: rawTar(
		rawEntry{name: "d/", typeflag: tar.TypeDir, mode: 0},
	)},
	"a mode-0 directory holding a file": {wantExtract: true, data: rawTar(
		rawEntry{name: "d/", typeflag: tar.TypeDir, mode: 0},
		rawEntry{name: "d/f", typeflag: tar.TypeReg, body: "x", mode: 0o644},
	)},
	"a directory created through an in-archive symlink": {wantExtract: false, data: rawTar(
		rawEntry{name: "c/", typeflag: tar.TypeDir, mode: 0o755},
		rawEntry{name: "a", typeflag: tar.TypeSymlink, linkname: "c"},
		rawEntry{name: "a/d/", typeflag: tar.TypeDir, mode: 0o755},
	)},
	"a directory entry over an in-archive symlink to a dir": {wantExtract: false, data: rawTar(
		rawEntry{name: "c/", typeflag: tar.TypeDir, mode: 0o755},
		rawEntry{name: "a", typeflag: tar.TypeSymlink, linkname: "c"},
		rawEntry{name: "a/", typeflag: tar.TypeDir, mode: 0o755},
	)},
	"a symlink created through an in-archive symlink": {wantExtract: false, data: rawTar(
		rawEntry{name: "c/", typeflag: tar.TypeDir, mode: 0o755},
		rawEntry{name: "a", typeflag: tar.TypeSymlink, linkname: "c"},
		rawEntry{name: "a/x", typeflag: tar.TypeSymlink, linkname: "y"},
	)},
	"a duplicate regular file with a narrower second mode": {wantExtract: true, data: rawTar(
		rawEntry{name: "f", typeflag: tar.TypeReg, body: "first", mode: 0o755},
		rawEntry{name: "f", typeflag: tar.TypeReg, body: "second", mode: 0o600},
	)},
	"a deep file with implicit parents, then its parent as an explicit dir": {wantExtract: true, data: rawTar(
		rawEntry{name: "p/q/r/f", typeflag: tar.TypeReg, body: "x", mode: 0o644},
		rawEntry{name: "p/q/", typeflag: tar.TypeDir, mode: 0o755},
	)},
	"a dangling relative symlink": {wantExtract: true, data: rawTar(
		rawEntry{name: "s/l", typeflag: tar.TypeSymlink, linkname: "missing"},
	)},
	"a dot directory entry and a skipped hardlink": {wantExtract: true, data: rawTar(
		rawEntry{name: "./", typeflag: tar.TypeDir, mode: 0o755},
		rawEntry{name: "f", typeflag: tar.TypeReg, body: "x", mode: 0o644},
		rawEntry{name: "h", typeflag: tar.TypeLink, linkname: "f"},
	)},
}

var _ = Describe("extraction and verification round trip", func() {
	lim := archive.Limits{MaxFileBytes: 4 << 10, MaxTotalBytes: 64 << 10, MaxEntries: 256}

	// The same invariant FuzzExtractTarZst enforces on mutated input: only
	// where extraction succeeds, since a seed may be refused for good reason.
	expectRoundTrip := func(data []byte) {
		dest := filepath.Join(GinkgoT().TempDir(), "dest")
		if err := extractTar(bytes.NewReader(data), dest, lim); err != nil {
			return
		}
		Expect(verifyExtractedTar(bytes.NewReader(data), dest, lim)).To(Succeed(),
			"a tree extraction produced must verify against the same bytes")
	}

	It("holds for every fuzz seed", func() {
		for _, seed := range extractFuzzSeeds() {
			expectRoundTrip(seed)
		}
	})

	for name, shape := range roundTripShapes {
		It("extracts as declared and round-trips: "+name, func() {
			dest := filepath.Join(GinkgoT().TempDir(), "dest")
			err := extractTar(bytes.NewReader(shape.data), dest, lim)
			if !shape.wantExtract {
				Expect(err).To(HaveOccurred(), "extraction must refuse this archive")
				return
			}
			Expect(err).NotTo(HaveOccurred(), "extraction must accept this archive")
			Expect(verifyExtractedTar(bytes.NewReader(shape.data), dest, lim)).To(Succeed(),
				"a tree extraction produced must verify against the same bytes")
		})
	}

	DescribeTable("extraction refuses an entry routed through or onto an in-archive symlink",
		func(name string) {
			dest := filepath.Join(GinkgoT().TempDir(), "dest")
			err := extractTar(bytes.NewReader(roundTripShapes[name].data), dest, lim)
			Expect(err).To(MatchError(ContainSubstring("symlink")))
		},
		Entry(nil, "a file written through an in-archive symlink to a dir"),
		Entry(nil, "a regular file over an earlier symlink"),
		Entry(nil, "a directory created through an in-archive symlink"),
		Entry(nil, "a directory entry over an in-archive symlink to a dir"),
		Entry(nil, "a symlink created through an in-archive symlink"),
	)

	It("leaves a regular file readable by its owner whatever its archive mode", func() {
		dest := filepath.Join(GinkgoT().TempDir(), "dest")
		Expect(extractTar(bytes.NewReader(roundTripShapes["a write-only regular file"].data), dest, lim)).To(Succeed())
		info, err := os.Stat(filepath.Join(dest, "w"))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm() & 0o400).NotTo(BeZero())
		Expect(info.Mode().Perm()&0o200).NotTo(BeZero(), "the archive's own bits are kept")
	})

	It("leaves an explicit directory usable by its owner whatever its archive mode", func() {
		dest := filepath.Join(GinkgoT().TempDir(), "dest")
		Expect(extractTar(bytes.NewReader(roundTripShapes["a mode-0 directory holding a file"].data), dest, lim)).To(Succeed())
		info, err := os.Stat(filepath.Join(dest, "d"))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm() & 0o700).To(Equal(os.FileMode(0o700)))
	})
})
