package source

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("VerifyExtractedTarZst", func() {
	var (
		archive []byte
		dest    string
	)

	BeforeEach(func() {
		archive = buildArchive(
			tarEntry{name: "polypkg.yaml", typeflag: tar.TypeReg, body: []byte("schema: x\n"), mode: 0o644},
			tarEntry{name: "content/bin/hi", typeflag: tar.TypeReg, body: []byte("#!/bin/sh\necho hi\n"), mode: 0o755},
			tarEntry{name: "content/bin/hello", typeflag: tar.TypeSymlink, linkname: "hi"},
		)
		dest = filepath.Join(GinkgoT().TempDir(), "tree")
		Expect(ExtractTarZst(bytes.NewReader(archive), dest)).To(Succeed())
	})

	verify := func() error { return VerifyExtractedTarZst(bytes.NewReader(archive), dest) }

	It("accepts the tree extraction produced", func() {
		Expect(verify()).To(Succeed())
	})

	It("accepts a file that lost permission bits, as the umask removes them at extraction", func() {
		Expect(os.Chmod(filepath.Join(dest, "content/bin/hi"), 0o700)).To(Succeed())
		Expect(verify()).To(Succeed())
	})

	It("accepts a later duplicate entry, which extraction lets win", func() {
		archive = buildArchive(
			tarEntry{name: "f", typeflag: tar.TypeReg, body: []byte("first\n")},
			tarEntry{name: "f", typeflag: tar.TypeReg, body: []byte("second\n")},
		)
		dest = filepath.Join(GinkgoT().TempDir(), "dup")
		Expect(ExtractTarZst(bytes.NewReader(archive), dest)).To(Succeed())
		Expect(verify()).To(Succeed())
	})

	It("accepts a later duplicate with a narrower mode, as extraction keeps the first file's mode", func() {
		// O_TRUNC rewrites the content but never re-applies a mode to an
		// existing file, so the first entry's mode is the one on disk.
		archive = buildArchive(
			tarEntry{name: "f", typeflag: tar.TypeReg, body: []byte("first\n"), mode: 0o755},
			tarEntry{name: "f", typeflag: tar.TypeReg, body: []byte("second\n"), mode: 0o600},
		)
		dest = filepath.Join(GinkgoT().TempDir(), "dupmode")
		Expect(ExtractTarZst(bytes.NewReader(archive), dest)).To(Succeed())
		Expect(verify()).To(Succeed())
	})

	DescribeTable("reports a modified tree as ErrExtractedTreeMismatch",
		func(tamper func()) {
			tamper()
			Expect(verify()).To(MatchError(ErrExtractedTreeMismatch))
		},
		Entry("a same-size content edit", func() {
			Expect(os.WriteFile(filepath.Join(dest, "content/bin/hi"), []byte("#!/bin/sh\necho HI\n"), 0o755)).To(Succeed())
		}),
		Entry("appended content", func() {
			f, err := os.OpenFile(filepath.Join(dest, "content/bin/hi"), os.O_WRONLY|os.O_APPEND, 0)
			Expect(err).NotTo(HaveOccurred())
			_, err = f.WriteString("echo injected\n")
			Expect(err).NotTo(HaveOccurred())
			Expect(f.Close()).To(Succeed())
		}),
		Entry("a deleted file", func() {
			Expect(os.Remove(filepath.Join(dest, "polypkg.yaml"))).To(Succeed())
		}),
		Entry("a permission bit the archive does not grant", func() {
			Expect(os.Chmod(filepath.Join(dest, "polypkg.yaml"), 0o666)).To(Succeed())
		}),
		Entry("a regular file replaced by a symlink", func() {
			p := filepath.Join(dest, "content/bin/hi")
			Expect(os.Remove(p)).To(Succeed())
			Expect(os.Symlink("../../polypkg.yaml", p)).To(Succeed())
		}),
		Entry("a retargeted symlink", func() {
			p := filepath.Join(dest, "content/bin/hello")
			Expect(os.Remove(p)).To(Succeed())
			Expect(os.Symlink("../../polypkg.yaml", p)).To(Succeed())
		}),
		Entry("a symlink replaced by a regular file", func() {
			p := filepath.Join(dest, "content/bin/hello")
			Expect(os.Remove(p)).To(Succeed())
			Expect(os.WriteFile(p, []byte("#!/bin/sh\necho hi\n"), 0o755)).To(Succeed())
		}),
		Entry("a planted extra file", func() {
			Expect(os.WriteFile(filepath.Join(dest, "content/bin/extra"), []byte("x"), 0o755)).To(Succeed())
		}),
		Entry("a planted extra directory", func() {
			Expect(os.Mkdir(filepath.Join(dest, "content/lib"), 0o755)).To(Succeed())
		}),
		Entry("a parent directory swapped for a symlink to an identical copy", func() {
			Expect(os.Rename(filepath.Join(dest, "content"), filepath.Join(dest, "content.real"))).To(Succeed())
			Expect(os.Symlink("content.real", filepath.Join(dest, "content"))).To(Succeed())
		}),
	)

	It("reports an unreadable file as a mismatch, not a hard error", func() {
		if os.Geteuid() == 0 {
			Skip("root bypasses file permission checks")
		}
		p := filepath.Join(dest, "content/bin/hi")
		Expect(os.Chmod(p, 0o000)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(p, 0o755) })
		Expect(verify()).To(MatchError(ErrExtractedTreeMismatch))
	})

	It("refuses, as extraction does, an archive that writes onto an in-archive symlink", func() {
		archive = buildArchive(
			tarEntry{name: "t", typeflag: tar.TypeReg, body: []byte("target")},
			tarEntry{name: "l", typeflag: tar.TypeSymlink, linkname: "t"},
			tarEntry{name: "l", typeflag: tar.TypeReg, body: []byte("over")},
		)
		err := verify()
		Expect(err).To(MatchError(ContainSubstring("replaces the symlink l")))
		Expect(err).NotTo(MatchError(ErrExtractedTreeMismatch))
	})

	It("returns a non-mismatch error when the archive itself cannot be read", func() {
		err := VerifyExtractedTarZst(bytes.NewReader([]byte("not a zstd stream")), dest)
		Expect(err).To(HaveOccurred())
		Expect(err).NotTo(MatchError(ErrExtractedTreeMismatch))
	})
})
