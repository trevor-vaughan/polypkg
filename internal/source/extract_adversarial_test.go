package source

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// tarEntry describes one archive member for adversarial extraction tests.
type tarEntry struct {
	name     string
	typeflag byte
	linkname string
	body     []byte
	mode     int64
}

// buildTar builds an uncompressed tar stream from the given entries verbatim —
// no sanitization — so tests can encode hostile archives. tar/zstd encoder
// errors against an in-memory buffer are "should-never-happen": we panic so
// the helper is callable from both Ginkgo specs and *testing.F fuzz seeds
// without needing a *testing.T or *testing.F parameter (testing.TB is sealed
// and GinkgoT() cannot satisfy it).
func buildTar(entries ...tarEntry) []byte {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		if err := tw.WriteHeader(&tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Linkname: e.linkname,
			Mode:     mode,
			Size:     int64(len(e.body)),
		}); err != nil {
			panic(fmt.Sprintf("tar.WriteHeader: %v", err))
		}
		if len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				panic(fmt.Sprintf("tar.Write: %v", err))
			}
		}
	}
	if err := tw.Close(); err != nil {
		panic(fmt.Sprintf("tar.Close: %v", err))
	}
	return raw.Bytes()
}

// buildArchive wraps buildTar in zstd to produce a full tar.zst stream.
func buildArchive(entries ...tarEntry) []byte {
	var z bytes.Buffer
	enc, err := zstd.NewWriter(&z)
	if err != nil {
		panic(fmt.Sprintf("zstd.NewWriter: %v", err))
	}
	if _, err := enc.Write(buildTar(entries...)); err != nil {
		panic(fmt.Sprintf("zstd.Write: %v", err))
	}
	if err := enc.Close(); err != nil {
		panic(fmt.Sprintf("zstd.Close: %v", err))
	}
	return z.Bytes()
}

// noEscape asserts the canary directory (a sibling of dest) is still empty,
// proving extraction wrote nothing outside dest.
func noEscape(outside string) {
	ents, err := os.ReadDir(outside)
	Expect(err).NotTo(HaveOccurred())
	Expect(ents).To(BeEmpty(), "extraction must not have written anything outside dest")
}

var _ = Describe("ExtractTarZst adversarial inputs", func() {
	It("rejects a deep ../../ traversal in the entry name", func() {
		dest := GinkgoT().TempDir()
		archive := buildArchive(tarEntry{name: "../../../../etc/passwd", typeflag: tar.TypeReg, body: []byte("x")})
		err := ExtractTarZst(bytes.NewReader(archive), dest)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("traversal"))
	})

	It("rejects an absolute path in the entry name", func() {
		dest := GinkgoT().TempDir()
		archive := buildArchive(tarEntry{name: "/etc/cron.d/pwned", typeflag: tar.TypeReg, body: []byte("x")})
		err := ExtractTarZst(bytes.NewReader(archive), dest)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("traversal"))
	})

	It("rejects a symlink with an absolute target", func() {
		dest := GinkgoT().TempDir()
		archive := buildArchive(tarEntry{name: "link", typeflag: tar.TypeSymlink, linkname: "/etc"})
		err := ExtractTarZst(bytes.NewReader(archive), dest)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("traversal"))
		_, statErr := os.Lstat(filepath.Join(dest, "link"))
		Expect(statErr).To(HaveOccurred(), "the escaping link must not be created")
	})

	It("rejects a relative symlink that escapes the tree", func() {
		dest := GinkgoT().TempDir()
		archive := buildArchive(tarEntry{name: "sub/link", typeflag: tar.TypeSymlink, linkname: "../../../../outside"})
		err := ExtractTarZst(bytes.NewReader(archive), dest)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("traversal"))
	})

	// SymlinkThenWriteThrough: the classic two-step attack inside one archive — a
	// symlink that escapes, then a file written through it. The escaping link is
	// refused at creation, so the follow-up never lands.
	It("refuses a symlink-then-write-through attack within one archive", func() {
		dest, outside := GinkgoT().TempDir(), GinkgoT().TempDir()
		archive := buildArchive(
			tarEntry{name: "evil", typeflag: tar.TypeSymlink, linkname: "../" + filepath.Base(outside)},
			tarEntry{name: "evil/pwned", typeflag: tar.TypeReg, body: []byte("x")},
		)
		err := ExtractTarZst(bytes.NewReader(archive), dest)
		Expect(err).To(HaveOccurred())
		noEscape(outside)
	})

	// PreplantedSymlinkWriteThrough: the strongest test of os.Root itself. A symlink
	// that escapes already exists in dest (an attacker-planted or leftover link
	// that bypassed any creation-time check); a regular-file entry then tries to
	// write through it. os.Root must refuse to traverse it.
	It("refuses to write through a pre-existing escaping symlink", func() {
		dest, outside := GinkgoT().TempDir(), GinkgoT().TempDir()
		Expect(os.Symlink(outside, filepath.Join(dest, "evil"))).To(Succeed())

		archive := buildArchive(tarEntry{name: "evil/pwned", typeflag: tar.TypeReg, body: []byte("x")})
		err := ExtractTarZst(bytes.NewReader(archive), dest)
		Expect(err).To(HaveOccurred(), "os.Root must refuse to write through an escaping symlink")
		noEscape(outside)
	})

	// PreplantedSymlinkDirectWrite: writing directly onto a pre-existing escaping
	// symlink (no subpath) must also be refused, not followed to truncate the
	// outside target.
	It("refuses to overwrite directly onto a pre-existing escaping symlink", func() {
		dest, outside := GinkgoT().TempDir(), GinkgoT().TempDir()
		victim := filepath.Join(outside, "victim")
		Expect(os.WriteFile(victim, []byte("original"), 0o600)).To(Succeed())
		Expect(os.Symlink(victim, filepath.Join(dest, "evil"))).To(Succeed())

		archive := buildArchive(tarEntry{name: "evil", typeflag: tar.TypeReg, body: []byte("overwritten")})
		err := ExtractTarZst(bytes.NewReader(archive), dest)
		Expect(err).To(HaveOccurred())
		got, readErr := os.ReadFile(victim)
		Expect(readErr).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("original"), "the outside victim file must be untouched")
	})

	// AllowsRelativeSymlinkWithinTree: a legitimate relative symlink that stays
	// inside the tree is created and resolves correctly.
	It("allows a relative symlink that stays within the tree", func() {
		dest := GinkgoT().TempDir()
		archive := buildArchive(
			tarEntry{name: "target", typeflag: tar.TypeReg, body: []byte("hi")},
			tarEntry{name: "link", typeflag: tar.TypeSymlink, linkname: "target"},
		)
		Expect(ExtractTarZst(bytes.NewReader(archive), dest)).To(Succeed())

		got, err := os.Readlink(filepath.Join(dest, "link"))
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("target"))
		content, err := os.ReadFile(filepath.Join(dest, "link"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(content)).To(Equal("hi"), "reading through the in-tree link works")
	})

	// SkipsSpecialEntries: device, fifo, and hardlink members are silently skipped,
	// never created — they have no place in a package tree and could reference
	// arbitrary inodes.
	It("silently skips device, fifo, and hardlink members", func() {
		dest := GinkgoT().TempDir()
		archive := buildArchive(
			tarEntry{name: "chardev", typeflag: tar.TypeChar},
			tarEntry{name: "blockdev", typeflag: tar.TypeBlock},
			tarEntry{name: "pipe", typeflag: tar.TypeFifo},
			tarEntry{name: "hard", typeflag: tar.TypeLink, linkname: "/etc/passwd"},
			tarEntry{name: "real", typeflag: tar.TypeReg, body: []byte("ok")},
		)
		Expect(ExtractTarZst(bytes.NewReader(archive), dest)).To(Succeed())

		for _, skipped := range []string{"chardev", "blockdev", "pipe", "hard"} {
			_, err := os.Lstat(filepath.Join(dest, skipped))
			Expect(err).To(HaveOccurred(), "%s must be skipped", skipped)
		}
		got, err := os.ReadFile(filepath.Join(dest, "real"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("ok"))
	})
})
