package archive

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// member is one tar entry, written verbatim (mode included) so specs can
// encode hostile archives.
type member struct {
	name, linkname, body string
	typeflag             byte
	mode                 int64
}

// tarOf builds a tar stream from members. It panics on a writer error rather
// than asserting, so the fuzz target can build its seeds outside Ginkgo.
func tarOf(members ...member) []byte {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, m := range members {
		if err := tw.WriteHeader(&tar.Header{
			Name: m.name, Linkname: m.linkname, Typeflag: m.typeflag,
			Mode: m.mode, Size: int64(len(m.body)),
		}); err != nil {
			panic(fmt.Sprintf("tar.WriteHeader: %v", err))
		}
		if _, err := tw.Write([]byte(m.body)); err != nil {
			panic(fmt.Sprintf("tar.Write: %v", err))
		}
	}
	if err := tw.Close(); err != nil {
		panic(fmt.Sprintf("tar.Close: %v", err))
	}
	return raw.Bytes()
}

// sandbox creates base/root and an empty sibling base/outside, and opens an
// os.Root on base/root. It returns the root and base.
func sandbox() (*os.Root, string) {
	base := GinkgoT().TempDir()
	Expect(os.Mkdir(filepath.Join(base, "root"), 0o700)).To(Succeed())
	Expect(os.Mkdir(filepath.Join(base, "outside"), 0o700)).To(Succeed())
	root, err := os.OpenRoot(filepath.Join(base, "root"))
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(root.Close)
	return root, base
}

// expectContained asserts extraction wrote nothing beside the root: base
// still holds only root and an empty outside.
func expectContained(base string) {
	ents, err := os.ReadDir(base)
	Expect(err).NotTo(HaveOccurred())
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	Expect(names).To(ConsistOf("outside", "root"))
	outside, err := os.ReadDir(filepath.Join(base, "outside"))
	Expect(err).NotTo(HaveOccurred())
	Expect(outside).To(BeEmpty(), "extraction must not have written outside the root")
}

var pkgOpts = Options{Policy: PolicyPackage, Limits: DefaultLimits(), DirPerm: 0o750}

var _ = Describe("DefaultLimits", func() {
	It("is 1 GiB per file, 2 GiB in total and 100 000 members", func() {
		Expect(DefaultLimits()).To(Equal(Limits{MaxFileBytes: 1 << 30, MaxTotalBytes: 2 << 30, MaxEntries: 100_000}))
	})
})

var _ = Describe("ExtractTar under PolicyPackage", func() {
	It("reports everything it creates, in archive order", func() {
		root, base := sandbox()
		data := tarOf(
			member{name: "bin/", typeflag: tar.TypeDir, mode: 0o755},
			member{name: "bin/hi", typeflag: tar.TypeReg, body: "#!/bin/sh\n", mode: 0o755},
			member{name: "lib/x/y", typeflag: tar.TypeReg, body: "y", mode: 0o644},
			member{name: "bin/hello", typeflag: tar.TypeSymlink, linkname: "hi"},
		)
		placed, err := ExtractTar(bytes.NewReader(data), root, pkgOpts)
		Expect(err).NotTo(HaveOccurred())
		Expect(placed).To(Equal([]Placed{
			{Path: "bin", Kind: "dir", Mode: 0o755},
			{Path: "bin/hi", Kind: "file", Mode: 0o755},
			{Path: "lib", Kind: "dir", Mode: 0o750},
			{Path: "lib/x", Kind: "dir", Mode: 0o750},
			{Path: "lib/x/y", Kind: "file", Mode: 0o644},
			{Path: "bin/hello", Kind: "symlink", Target: "hi"},
		}))
		got, err := root.ReadFile("lib/x/y")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("y"))
		target, err := root.Readlink("bin/hello")
		Expect(err).NotTo(HaveOccurred())
		Expect(target).To(Equal("hi"))
		expectContained(base)
	})

	It("records a path once, at its first placement", func() {
		root, _ := sandbox()
		data := tarOf(
			member{name: "f", typeflag: tar.TypeReg, body: "first", mode: 0o755},
			member{name: "f", typeflag: tar.TypeReg, body: "second", mode: 0o600},
			member{name: "d/", typeflag: tar.TypeDir, mode: 0o755},
			member{name: "d/", typeflag: tar.TypeDir, mode: 0o700},
			member{name: "./", typeflag: tar.TypeDir, mode: 0o755},
		)
		placed, err := ExtractTar(bytes.NewReader(data), root, pkgOpts)
		Expect(err).NotTo(HaveOccurred())
		Expect(placed).To(Equal([]Placed{
			{Path: "f", Kind: "file", Mode: 0o755},
			{Path: "d", Kind: "dir", Mode: 0o755},
		}))
		got, err := root.ReadFile("f")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("second"), "a later duplicate rewrites the content")
	})

	It("does not report a directory that already existed under the root", func() {
		root, base := sandbox()
		Expect(os.Mkdir(filepath.Join(base, "root", "pre"), 0o700)).To(Succeed())
		data := tarOf(member{name: "pre/f", typeflag: tar.TypeReg, body: "x", mode: 0o644})
		placed, err := ExtractTar(bytes.NewReader(data), root, pkgOpts)
		Expect(err).NotTo(HaveOccurred())
		Expect(placed).To(Equal([]Placed{{Path: "pre/f", Kind: "file", Mode: 0o644}}))
	})

	It("reports a regular file that already existed under the root when a member rewrites it", func() {
		root, base := sandbox()
		Expect(os.WriteFile(filepath.Join(base, "root", "pre"), []byte("old"), 0o600)).To(Succeed())
		data := tarOf(member{name: "pre", typeflag: tar.TypeReg, body: "new", mode: 0o644})
		placed, err := ExtractTar(bytes.NewReader(data), root, pkgOpts)
		Expect(err).NotTo(HaveOccurred())
		Expect(placed).To(Equal([]Placed{{Path: "pre", Kind: "file", Mode: 0o644}}))
		got, err := root.ReadFile("pre")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("new"))
	})

	DescribeTable("records missing ancestors with the mode of the member that needs them",
		func(m member, want []Placed) {
			root, _ := sandbox()
			placed, err := ExtractTar(bytes.NewReader(tarOf(m)), root, pkgOpts)
			Expect(err).NotTo(HaveOccurred())
			Expect(placed).To(Equal(want))
		},
		Entry("an explicit directory takes its own mode for its ancestors",
			member{name: "x/y/", typeflag: tar.TypeDir, mode: 0o755},
			[]Placed{{Path: "x", Kind: "dir", Mode: 0o755}, {Path: "x/y", Kind: "dir", Mode: 0o755}}),
		Entry("a file's parents take DirPerm",
			member{name: "x/y/f", typeflag: tar.TypeReg, body: "f", mode: 0o644},
			[]Placed{{Path: "x", Kind: "dir", Mode: 0o750}, {Path: "x/y", Kind: "dir", Mode: 0o750}, {Path: "x/y/f", Kind: "file", Mode: 0o644}}),
		Entry("a symlink's parents take DirPerm",
			member{name: "x/l", typeflag: tar.TypeSymlink, linkname: "t"},
			[]Placed{{Path: "x", Kind: "dir", Mode: 0o750}, {Path: "x/l", Kind: "symlink", Target: "t"}}),
	)

	It("keeps owner access whatever the archive mode", func() {
		root, _ := sandbox()
		data := tarOf(
			member{name: "d/", typeflag: tar.TypeDir, mode: 0},
			member{name: "d/w", typeflag: tar.TypeReg, body: "x", mode: 0o200},
		)
		placed, err := ExtractTar(bytes.NewReader(data), root, pkgOpts)
		Expect(err).NotTo(HaveOccurred())
		Expect(placed).To(Equal([]Placed{
			{Path: "d", Kind: "dir", Mode: 0o700},
			{Path: "d/w", Kind: "file", Mode: 0o600},
		}))
	})

	It("skips hardlinks, devices and FIFOs without creating or reporting them", func() {
		root, _ := sandbox()
		data := tarOf(
			member{name: "real", typeflag: tar.TypeReg, body: "ok", mode: 0o644},
			member{name: "chardev", typeflag: tar.TypeChar, mode: 0o644},
			member{name: "blockdev", typeflag: tar.TypeBlock, mode: 0o644},
			member{name: "pipe", typeflag: tar.TypeFifo, mode: 0o644},
			member{name: "hard", typeflag: tar.TypeLink, linkname: "real", mode: 0o644},
		)
		placed, err := ExtractTar(bytes.NewReader(data), root, pkgOpts)
		Expect(err).NotTo(HaveOccurred())
		Expect(placed).To(Equal([]Placed{{Path: "real", Kind: "file", Mode: 0o644}}))
		for _, skipped := range []string{"chardev", "blockdev", "pipe", "hard"} {
			_, err := root.Lstat(skipped)
			Expect(err).To(MatchError(fs.ErrNotExist), "%s must be skipped", skipped)
		}
	})

	DescribeTable("refuses a setuid, setgid or sticky mode",
		func(m member) {
			root, _ := sandbox()
			placed, err := ExtractTar(bytes.NewReader(tarOf(m)), root, pkgOpts)
			Expect(err).To(MatchError(ContainSubstring("unsupported file mode")))
			Expect(placed).To(BeNil())
			_, statErr := root.Lstat(m.name)
			Expect(statErr).To(MatchError(fs.ErrNotExist))
		},
		Entry("a setuid file", member{name: "f", typeflag: tar.TypeReg, body: "x", mode: 0o4755}),
		Entry("a setgid file", member{name: "f", typeflag: tar.TypeReg, body: "x", mode: 0o2755}),
		Entry("a sticky directory", member{name: "d", typeflag: tar.TypeDir, mode: 0o1777}),
	)

	Describe("limits", func() {
		It("refuses a file over the per-file limit before creating it", func() {
			root, _ := sandbox()
			opts := pkgOpts
			opts.Limits = Limits{MaxFileBytes: 10, MaxTotalBytes: 1000, MaxEntries: 100}
			data := tarOf(member{name: "big", typeflag: tar.TypeReg, body: string(make([]byte, 20)), mode: 0o644})
			placed, err := ExtractTar(bytes.NewReader(data), root, opts)
			Expect(err).To(MatchError(ContainSubstring("big declares 20 bytes, exceeds limit 10")))
			Expect(placed).To(BeNil())
			_, statErr := root.Lstat("big")
			Expect(statErr).To(MatchError(fs.ErrNotExist))
		})

		It("refuses files that together exceed the total limit", func() {
			root, _ := sandbox()
			opts := pkgOpts
			opts.Limits = Limits{MaxFileBytes: 10, MaxTotalBytes: 12, MaxEntries: 100}
			data := tarOf(
				member{name: "a", typeflag: tar.TypeReg, body: "12345678", mode: 0o644},
				member{name: "b", typeflag: tar.TypeReg, body: "12345678", mode: 0o644},
			)
			placed, err := ExtractTar(bytes.NewReader(data), root, opts)
			Expect(err).To(MatchError(ContainSubstring("total size would exceed limit 12")))
			Expect(placed).To(BeNil())
		})

		It("counts skipped members against the entry limit", func() {
			root, _ := sandbox()
			opts := pkgOpts
			opts.Limits = Limits{MaxFileBytes: 100, MaxTotalBytes: 1000, MaxEntries: 2}
			data := tarOf(
				member{name: "p1", typeflag: tar.TypeFifo, mode: 0o644},
				member{name: "p2", typeflag: tar.TypeFifo, mode: 0o644},
				member{name: "f", typeflag: tar.TypeReg, body: "x", mode: 0o644},
			)
			placed, err := ExtractTar(bytes.NewReader(data), root, opts)
			Expect(err).To(MatchError(ContainSubstring("archive exceeds 2 entries")))
			Expect(placed).To(BeNil())
		})
	})

	DescribeTable("refuses a member that would escape the root",
		func(m member) {
			root, base := sandbox()
			placed, err := ExtractTar(bytes.NewReader(tarOf(m)), root, pkgOpts)
			Expect(err).To(MatchError(ContainSubstring("path traversal rejected")))
			Expect(placed).To(BeNil())
			expectContained(base)
		},
		Entry("a ../ name", member{name: "../escape", typeflag: tar.TypeReg, body: "x", mode: 0o644}),
		Entry("a deep ../ name", member{name: "../../../../etc/passwd", typeflag: tar.TypeReg, body: "x", mode: 0o644}),
		Entry("an absolute name", member{name: "/etc/cron.d/pwned", typeflag: tar.TypeReg, body: "x", mode: 0o644}),
		Entry("an absolute symlink target", member{name: "link", typeflag: tar.TypeSymlink, linkname: "/etc"}),
		Entry("a relative symlink target that escapes", member{name: "sub/link", typeflag: tar.TypeSymlink, linkname: "../../outside"}),
	)

	It("refuses a member routed through a symlink the archive created", func() {
		root, base := sandbox()
		data := tarOf(
			member{name: "c/", typeflag: tar.TypeDir, mode: 0o755},
			member{name: "a", typeflag: tar.TypeSymlink, linkname: "c"},
			member{name: "a/b", typeflag: tar.TypeReg, body: "x", mode: 0o644},
		)
		placed, err := ExtractTar(bytes.NewReader(data), root, pkgOpts)
		Expect(err).To(MatchError(ContainSubstring("a/b passes through or replaces the symlink a")))
		Expect(placed).To(BeNil())
		_, statErr := root.Lstat("c/b")
		Expect(statErr).To(MatchError(fs.ErrNotExist))
		expectContained(base)
	})

	It("refuses to write through a symlink already under the root", func() {
		root, base := sandbox()
		outside := filepath.Join(base, "outside")
		Expect(os.Symlink(outside, filepath.Join(base, "root", "evil"))).To(Succeed())
		data := tarOf(member{name: "evil/pwned", typeflag: tar.TypeReg, body: "x", mode: 0o644})
		placed, err := ExtractTar(bytes.NewReader(data), root, pkgOpts)
		Expect(err).To(MatchError(ContainSubstring("evil/pwned passes through or replaces the symlink evil")))
		Expect(placed).To(BeNil())
		expectContained(base)
	})

	It("refuses to write onto a symlink already under the root", func() {
		root, base := sandbox()
		victim := filepath.Join(base, "victim")
		Expect(os.WriteFile(victim, []byte("original"), 0o600)).To(Succeed())
		Expect(os.Symlink(victim, filepath.Join(base, "root", "evil"))).To(Succeed())
		data := tarOf(member{name: "evil", typeflag: tar.TypeReg, body: "overwritten", mode: 0o644})
		placed, err := ExtractTar(bytes.NewReader(data), root, pkgOpts)
		Expect(err).To(MatchError(ContainSubstring("evil passes through or replaces the symlink evil")))
		Expect(placed).To(BeNil())
		got, readErr := os.ReadFile(victim)
		Expect(readErr).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("original"), "the victim outside the root must be untouched")
	})

	DescribeTable("refuses options it cannot honour, before reading the archive",
		func(opts Options, want string) {
			root, base := sandbox()
			data := tarOf(member{name: "f", typeflag: tar.TypeReg, body: "x", mode: 0o644})
			placed, err := ExtractTar(bytes.NewReader(data), root, opts)
			Expect(err).To(MatchError(ContainSubstring(want)))
			Expect(placed).To(BeNil())
			ents, readErr := os.ReadDir(filepath.Join(base, "root"))
			Expect(readErr).NotTo(HaveOccurred())
			Expect(ents).To(BeEmpty())
		},
		Entry("the zero policy",
			Options{Limits: DefaultLimits(), DirPerm: 0o700}, "unknown extraction policy 0"),
		Entry("an undefined policy",
			Options{Policy: PolicyPackage + 100, Limits: DefaultLimits(), DirPerm: 0o700}, "unknown extraction policy"),
		Entry("the zero limits",
			Options{Policy: PolicyPackage, DirPerm: 0o700}, "extraction limits must be positive"),
		Entry("a negative limit",
			Options{Policy: PolicyPackage, Limits: Limits{MaxFileBytes: 1, MaxTotalBytes: -1, MaxEntries: 1}, DirPerm: 0o700}, "extraction limits must be positive"),
		Entry("a zero directory permission",
			Options{Policy: PolicyPackage, Limits: DefaultLimits()}, "directory permission"),
		Entry("a directory permission beyond the nine permission bits",
			Options{Policy: PolicyPackage, Limits: DefaultLimits(), DirPerm: fs.ModeSetgid | 0o755}, "directory permission"),
	)
})
