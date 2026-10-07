package action

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

const (
	appScript = "#!/bin/sh\necho app\n"
	appReadme = "app documentation\n"
)

// extractMember is one tar entry of an extract-action fixture archive.
type extractMember struct {
	name     string
	typeflag byte
	mode     int64
	body     string
	linkname string
}

// releaseMembers is shaped like an upstream release: one top-level directory,
// a setuid world-writable executable (normalised to 0o755), a relative
// in-archive symlink, and a world-writable document (normalised to 0o644)
// whose parent directories have no entries of their own.
var releaseMembers = []extractMember{
	{name: "app-1.0/", typeflag: tar.TypeDir, mode: 0o755},
	{name: "app-1.0/bin/", typeflag: tar.TypeDir, mode: 0o755},
	{name: "app-1.0/bin/app", typeflag: tar.TypeReg, mode: 0o4777, body: appScript},
	{name: "app-1.0/bin/app-link", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "app"},
	{name: "app-1.0/share/doc/README", typeflag: tar.TypeReg, mode: 0o666, body: appReadme},
}

// extractTarGz builds a gzip-compressed tar holding members, in order.
func extractTarGz(members ...extractMember) []byte {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, m := range members {
		Expect(tw.WriteHeader(&tar.Header{
			Name: m.name, Typeflag: m.typeflag, Mode: m.mode, Linkname: m.linkname, Size: int64(len(m.body)),
		})).To(Succeed())
		_, err := tw.Write([]byte(m.body))
		Expect(err).NotTo(HaveOccurred())
	}
	Expect(tw.Close()).To(Succeed())
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, err := zw.Write(raw.Bytes())
	Expect(err).NotTo(HaveOccurred())
	Expect(zw.Close()).To(Succeed())
	return gz.Bytes()
}

// extractZip builds a zip holding members, in order. A symlink member stores
// its target as its body, as zip tools do.
func extractZip(members ...extractMember) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range members {
		hdr := &zip.FileHeader{Name: m.name, Method: zip.Deflate}
		body := m.body
		switch m.typeflag {
		case tar.TypeDir:
			hdr.SetMode(fs.ModeDir | fs.FileMode(m.mode))
		case tar.TypeSymlink:
			hdr.SetMode(fs.ModeSymlink | fs.FileMode(m.mode))
			body = m.linkname
		default:
			hdr.SetMode(fs.FileMode(m.mode))
		}
		w, err := zw.CreateHeader(hdr)
		Expect(err).NotTo(HaveOccurred())
		_, err = w.Write([]byte(body))
		Expect(err).NotTo(HaveOccurred())
	}
	Expect(zw.Close()).To(Succeed())
	return buf.Bytes()
}

// extractFixture lays out a package whose files hold archive at
// content/app.tar.gz, and returns a user-scope Scope for package "hello"
// together with the archive's path. Nothing exists under ActiveRoot yet.
func extractFixture(archive []byte) (Scope, string) {
	dir := GinkgoT().TempDir()
	scope := Scope{
		ActiveRoot:  filepath.Join(dir, "active"),
		PackageName: "hello",
		PackageRoot: filepath.Join(dir, "pkg"),
	}
	src := filepath.Join(scope.PackageRoot, "content", "app.tar.gz")
	Expect(os.MkdirAll(filepath.Dir(src), 0o755)).To(Succeed())
	Expect(os.WriteFile(src, archive, 0o644)).To(Succeed())
	return scope, src
}

// extractInv builds an extract invocation. extra adds or overrides params; a
// nil value removes the param.
func extractInv(src, dest string, extra map[string]any) Invocation {
	params := map[string]any{"src": src, "dest": dest}
	for k, v := range extra {
		if v == nil {
			delete(params, k)
			continue
		}
		params[k] = v
	}
	return Invocation{Action: "extract", PackageName: "hello", Phase: PhasePostPlace, Params: params}
}

// expectNothingPlaced asserts that a refused extract left neither dest nor a
// temporary sibling of it behind.
func expectNothingPlaced(dest string) {
	_, err := os.Lstat(dest)
	Expect(errors.Is(err, fs.ErrNotExist)).To(BeTrue(), "dest must not exist after a refusal")
	siblings, err := os.ReadDir(filepath.Dir(dest))
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	Expect(err).NotTo(HaveOccurred())
	Expect(siblings).To(BeEmpty(), "no temporary directory may be left beside dest")
}

// resultsByPath keys results by their path relative to activeRoot, failing on
// a path reported twice.
func resultsByPath(activeRoot string, results []Result) map[string]schema.Expected {
	got := map[string]schema.Expected{}
	for i := range results {
		r := results[i]
		Expect(r.Action).To(Equal("extract"))
		Expect(r.Outcome).To(Equal("ok"))
		Expect(r.Stat.Inode).NotTo(BeZero(), "stat must be captured for %s", r.Path)
		rel, err := filepath.Rel(activeRoot, r.Path)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).NotTo(HaveKey(rel), "each placed path is reported once")
		got[rel] = r.Expected
	}
	return got
}

var _ = Describe("Extract", func() {
	It("places every entry and returns one result per placed path", func() {
		scope, src := extractFixture(extractTarGz(releaseMembers...))
		dest := filepath.Join(scope.ActiveRoot, "hello", "dist")

		results, err := Extract(extractInv(src, dest, map[string]any{"strip_components": 1}), scope)
		Expect(err).NotTo(HaveOccurred())

		Expect(results[0].Path).To(Equal(dest), "dest itself is reported first")
		Expect(resultsByPath(scope.ActiveRoot, results)).To(Equal(map[string]schema.Expected{
			"hello/dist":                  {FileType: "dir", Mode: "0700"},
			"hello/dist/bin":              {FileType: "dir", Mode: "0700"},
			"hello/dist/bin/app":          {FileType: "regular", ContentHash: blake3Hex([]byte(appScript)), Mode: "0755"},
			"hello/dist/bin/app-link":     {FileType: "symlink", Target: "app"},
			"hello/dist/share":            {FileType: "dir", Mode: "0700"},
			"hello/dist/share/doc":        {FileType: "dir", Mode: "0700"},
			"hello/dist/share/doc/README": {FileType: "regular", ContentHash: blake3Hex([]byte(appReadme)), Mode: "0644"},
		}))

		info, err := os.Lstat(filepath.Join(dest, "bin", "app"))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky)).To(BeZero(), "special bits are never applied")
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o755)))
		body, err := os.ReadFile(filepath.Join(dest, "share", "doc", "README"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(body)).To(Equal(appReadme))
	})

	It("puts the scope's directory mode and the normalised file modes on disk whatever the umask", func() {
		old := syscall.Umask(0o077)
		DeferCleanup(func() { syscall.Umask(old) })
		scope, src := extractFixture(extractTarGz(releaseMembers...))
		scope.DirMode = 0o755
		dest := filepath.Join(scope.ActiveRoot, "hello", "dist")

		results, err := Extract(extractInv(src, dest, map[string]any{"strip_components": 1}), scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(resultsByPath(scope.ActiveRoot, results)).To(HaveKeyWithValue("hello/dist/share", schema.Expected{FileType: "dir", Mode: "0755"}))

		for rel, want := range map[string]os.FileMode{
			".": 0o755, "bin": 0o755, "share": 0o755, "share/doc": 0o755,
			"bin/app": 0o755, "share/doc/README": 0o644,
		} {
			info, err := os.Lstat(filepath.Join(dest, rel))
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(want), "mode of %s", rel)
		}
	})

	It("extracts a zip archive with the same results as the equivalent tar", func() {
		tarScope, tarSrc := extractFixture(extractTarGz(releaseMembers...))
		tarResults, err := Extract(extractInv(tarSrc, filepath.Join(tarScope.ActiveRoot, "hello", "dist"),
			map[string]any{"strip_components": 1}), tarScope)
		Expect(err).NotTo(HaveOccurred())

		zipScope, zipSrc := extractFixture(extractZip(releaseMembers...))
		zipResults, err := Extract(extractInv(zipSrc, filepath.Join(zipScope.ActiveRoot, "hello", "dist"),
			map[string]any{"strip_components": 1}), zipScope)
		Expect(err).NotTo(HaveOccurred())

		Expect(resultsByPath(zipScope.ActiveRoot, zipResults)).To(Equal(resultsByPath(tarScope.ActiveRoot, tarResults)))
		body, err := os.ReadFile(filepath.Join(zipScope.ActiveRoot, "hello", "dist", "bin", "app"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(body)).To(Equal(appScript))
	})

	It("refuses a strip_components that removes every member and places nothing", func() {
		scope, src := extractFixture(extractTarGz(releaseMembers...))
		dest := filepath.Join(scope.ActiveRoot, "hello", "dist")

		_, err := Extract(extractInv(src, dest, map[string]any{"strip_components": 9}), scope)
		Expect(err).To(MatchError(SatisfyAll(
			ContainSubstring("app.tar.gz"),
			ContainSubstring("strip_components 9 removes every archive member (the shallowest has 1 path segment)"),
		)))
		expectNothingPlaced(dest)
	})

	It("refuses an include when strip_components removes every member name", func() {
		scope, src := extractFixture(extractTarGz(releaseMembers...))
		dest := filepath.Join(scope.ActiveRoot, "hello", "dist")

		_, err := Extract(extractInv(src, dest, map[string]any{"strip_components": 9, "include": []any{"bin"}}), scope)
		Expect(err).To(HaveOccurred())
		expectNothingPlaced(dest)
	})

	It("extracts only members an include pattern selects, by stripped path or ancestor", func() {
		scope, src := extractFixture(extractTarGz(releaseMembers...))
		dest := filepath.Join(scope.ActiveRoot, "hello", "dist")

		results, err := Extract(extractInv(src, dest, map[string]any{
			"strip_components": 1, "include": []any{"bin"},
		}), scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(resultsByPath(scope.ActiveRoot, results)).To(HaveLen(4))
		Expect(resultsByPath(scope.ActiveRoot, results)).To(SatisfyAll(
			HaveKey("hello/dist"), HaveKey("hello/dist/bin"),
			HaveKey("hello/dist/bin/app"), HaveKey("hello/dist/bin/app-link"),
		))
		_, err = os.Lstat(filepath.Join(dest, "share"))
		Expect(errors.Is(err, fs.ErrNotExist)).To(BeTrue())
	})

	It("refuses an include pattern that matches no member and places nothing", func() {
		scope, src := extractFixture(extractTarGz(releaseMembers...))
		dest := filepath.Join(scope.ActiveRoot, "hello", "dist")

		_, err := Extract(extractInv(src, dest, map[string]any{
			"strip_components": 1, "include": []any{"nope/*"},
		}), scope)
		Expect(err).To(HaveOccurred())
		expectNothingPlaced(dest)
	})

	DescribeTable("refuses malformed params before touching the filesystem",
		func(extra map[string]any, want string) {
			scope, src := extractFixture(extractTarGz(releaseMembers...))
			dest := filepath.Join(scope.ActiveRoot, "hello", "dist")

			_, err := Extract(extractInv(src, dest, extra), scope)
			Expect(err).To(MatchError(ContainSubstring(want)))
			_, statErr := os.Lstat(scope.ActiveRoot)
			Expect(errors.Is(statErr, fs.ErrNotExist)).To(BeTrue(), "nothing may be created")
		},
		Entry("missing src", map[string]any{"src": nil}, "missing required param 'src'"),
		Entry("missing dest", map[string]any{"dest": nil}, "missing required param 'dest'"),
		Entry("negative strip_components", map[string]any{"strip_components": -1}, "strip_components must be a non-negative integer"),
		Entry("non-numeric strip_components", map[string]any{"strip_components": "one"}, "strip_components must be a non-negative integer"),
		Entry("fractional strip_components", map[string]any{"strip_components": 1.5}, "strip_components must be a non-negative integer"),
		Entry("include as a bare string", map[string]any{"include": "bin"}, "include must be a non-empty list"),
		Entry("empty include", map[string]any{"include": []any{}}, "include must be a non-empty list"),
		Entry("non-string include entry", map[string]any{"include": []any{3}}, "is not a pattern string"),
		Entry("malformed include pattern", map[string]any{"include": []any{"bin/["}}, `include pattern "bin/[" is not a valid path.Match pattern`),
		Entry("empty include pattern", map[string]any{"include": []any{""}}, "include has an empty pattern"),
		Entry("strip_components beyond the member depth cap", map[string]any{"strip_components": 1e300},
			"strip_components must be at most 64, the deepest member path an archive may hold; got 1e+300"),
	)

	It("refuses a src outside the package's files", func() {
		scope, _ := extractFixture(extractTarGz(releaseMembers...))
		outside := filepath.Join(filepath.Dir(scope.PackageRoot), "outside.tar.gz")
		Expect(os.WriteFile(outside, extractTarGz(releaseMembers...), 0o644)).To(Succeed())
		dest := filepath.Join(scope.ActiveRoot, "hello", "dist")

		_, err := Extract(extractInv(outside, dest, nil), scope)
		Expect(err).To(MatchError(ContainSubstring("outside the package's files")))
		_, statErr := os.Lstat(scope.ActiveRoot)
		Expect(errors.Is(statErr, fs.ErrNotExist)).To(BeTrue())
	})

	It("refuses a src that is a directory", func() {
		scope, _ := extractFixture(extractTarGz(releaseMembers...))
		dest := filepath.Join(scope.ActiveRoot, "hello", "dist")

		_, err := Extract(extractInv(filepath.Join(scope.PackageRoot, "content"), dest, nil), scope)
		Expect(err).To(MatchError(ContainSubstring("is not a regular file")))
		expectNothingPlaced(dest)
	})

	It("follows a src symlink that stays within the package's files", func() {
		scope, src := extractFixture(extractTarGz(releaseMembers...))
		link := filepath.Join(scope.PackageRoot, "content", "current.tar.gz")
		Expect(os.Symlink(filepath.Base(src), link)).To(Succeed())
		dest := filepath.Join(scope.ActiveRoot, "hello", "dist")

		results, err := Extract(extractInv(link, dest, map[string]any{"strip_components": 1}), scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(resultsByPath(scope.ActiveRoot, results)).To(HaveKey("hello/dist/bin/app"))
	})

	It("refuses a src symlink that escapes the package's files", func() {
		scope, _ := extractFixture(extractTarGz(releaseMembers...))
		outside := filepath.Join(filepath.Dir(scope.PackageRoot), "outside.tar.gz")
		Expect(os.WriteFile(outside, extractTarGz(releaseMembers...), 0o644)).To(Succeed())
		link := filepath.Join(scope.PackageRoot, "content", "escape.tar.gz")
		Expect(os.Symlink(outside, link)).To(Succeed())
		dest := filepath.Join(scope.ActiveRoot, "hello", "dist")

		_, err := Extract(extractInv(link, dest, nil), scope)
		Expect(err).To(MatchError(ContainSubstring("escape.tar.gz")))
		_, statErr := os.Lstat(scope.ActiveRoot)
		Expect(errors.Is(statErr, fs.ErrNotExist)).To(BeTrue(), "nothing may be created")
	})

	It("refuses a FIFO src without blocking on it", func() {
		scope, _ := extractFixture(extractTarGz(releaseMembers...))
		fifo := filepath.Join(scope.PackageRoot, "content", "pipe.tar.gz")
		Expect(syscall.Mkfifo(fifo, 0o644)).To(Succeed())
		dest := filepath.Join(scope.ActiveRoot, "hello", "dist")

		done := make(chan error, 1)
		go func() {
			_, err := Extract(extractInv(fifo, dest, nil), scope)
			done <- err
		}()
		var err error
		Eventually(done, "5s").Should(Receive(&err), "opening a FIFO would block until a writer appears")
		Expect(err).To(MatchError(ContainSubstring("is not a regular file")))
		expectNothingPlaced(dest)
	})

	It("refuses a src that is not an archive", func() {
		scope, _ := extractFixture(extractTarGz(releaseMembers...))
		notes := filepath.Join(scope.PackageRoot, "content", "notes.txt")
		Expect(os.WriteFile(notes, []byte("plain text, not an archive\n"), 0o644)).To(Succeed())
		dest := filepath.Join(scope.ActiveRoot, "hello", "dist")

		_, err := Extract(extractInv(notes, dest, nil), scope)
		Expect(err).To(MatchError(ContainSubstring("notes.txt")))
		expectNothingPlaced(dest)
	})

	It("refuses a dest outside the package scope", func() {
		scope, src := extractFixture(extractTarGz(releaseMembers...))
		dest := filepath.Join(scope.ActiveRoot, "other", "dist")

		_, err := Extract(extractInv(src, dest, nil), scope)
		Expect(err).To(MatchError(ContainSubstring("outside the package scope")))
		_, statErr := os.Lstat(filepath.Join(scope.ActiveRoot, "other"))
		Expect(errors.Is(statErr, fs.ErrNotExist)).To(BeTrue(), "nothing may be created in another namespace")
	})

	It("refuses the package scope root itself as dest", func() {
		scope, src := extractFixture(extractTarGz(releaseMembers...))

		_, err := Extract(extractInv(src, filepath.Join(scope.ActiveRoot, "hello"), nil), scope)
		Expect(err).To(MatchError(ContainSubstring("is the package scope itself")))
	})

	It("refuses a dest that already exists and leaves it untouched", func() {
		scope, src := extractFixture(extractTarGz(releaseMembers...))
		dest := filepath.Join(scope.ActiveRoot, "hello", "dist")
		Expect(os.MkdirAll(dest, 0o755)).To(Succeed())
		marker := filepath.Join(dest, "keep")
		Expect(os.WriteFile(marker, []byte("mine"), 0o644)).To(Succeed())

		_, err := Extract(extractInv(src, dest, nil), scope)
		Expect(err).To(MatchError(ContainSubstring("already exists")))
		body, rerr := os.ReadFile(marker)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(body)).To(Equal("mine"))
		entries, rerr := os.ReadDir(filepath.Dir(dest))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(1), "no temporary directory may be left beside dest")
	})

	It("extracts into a dest whose name is as long as a file name may be", func() {
		scope, src := extractFixture(extractTarGz(releaseMembers...))
		dest := filepath.Join(scope.ActiveRoot, "hello", strings.Repeat("d", 250))

		results, err := Extract(extractInv(src, dest, map[string]any{"strip_components": 1}), scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(results[0].Path).To(Equal(dest))
		_, err = os.Lstat(filepath.Join(dest, "bin", "app"))
		Expect(err).NotTo(HaveOccurred())
	})

	It("refuses to replace a dest that appeared while the archive was extracted", func() {
		scope, src := extractFixture(extractTarGz(releaseMembers...))
		dest := filepath.Join(scope.ActiveRoot, "hello", "dist")
		beforeExtractRename = func() { Expect(os.Mkdir(dest, 0o755)).To(Succeed()) }
		DeferCleanup(func() { beforeExtractRename = nil })

		_, err := Extract(extractInv(src, dest, nil), scope)
		Expect(err).To(MatchError(ContainSubstring("already exists")))
		entries, rerr := os.ReadDir(dest)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty(), "the directory that appeared is left as it was")
		siblings, rerr := os.ReadDir(filepath.Dir(dest))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(siblings).To(HaveLen(1), "no temporary directory may be left beside dest")
	})

	It("removes the temporary directory when extraction panics", func() {
		scope, src := extractFixture(extractTarGz(releaseMembers...))
		dest := filepath.Join(scope.ActiveRoot, "hello", "dist")
		beforeExtractRename = func() { panic("injected") }
		DeferCleanup(func() { beforeExtractRename = nil })

		Expect(func() { _, _ = Extract(extractInv(src, dest, nil), scope) }).To(PanicWith("injected"))
		expectNothingPlaced(dest)
	})

	It("refuses to extract through a symlink planted to escape the scope", func() {
		scope, outside := plantEscape()
		src := filepath.Join(scope.PackageRoot, "app.tar.gz")
		Expect(os.WriteFile(src, extractTarGz(releaseMembers...), 0o644)).To(Succeed())
		dest := filepath.Join(scope.ActiveRoot, scope.PackageName, "evil", "dist")

		_, err := Extract(extractInv(src, dest, nil), scope)
		Expect(err).To(HaveOccurred())
		entries, rerr := os.ReadDir(outside)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty(), "nothing may be written outside the scope")
	})

	DescribeTable("refuses an archive the strict policy rejects and places nothing",
		func(bad extractMember) {
			members := []extractMember{
				{name: "app-1.0/bin/app", typeflag: tar.TypeReg, mode: 0o755, body: appScript},
				bad,
			}
			scope, src := extractFixture(extractTarGz(members...))
			dest := filepath.Join(scope.ActiveRoot, "hello", "dist")

			_, err := Extract(extractInv(src, dest, nil), scope)
			Expect(err).To(HaveOccurred())
			expectNothingPlaced(dest)
			for _, escaped := range []string{
				filepath.Join(scope.ActiveRoot, "evil"),
				filepath.Join(filepath.Dir(scope.ActiveRoot), "evil"),
			} {
				_, statErr := os.Lstat(escaped)
				Expect(errors.Is(statErr, fs.ErrNotExist)).To(BeTrue(), "%s must not exist", escaped)
			}
		},
		Entry("parent-directory traversal", extractMember{name: "../evil", typeflag: tar.TypeReg, mode: 0o644, body: "x"}),
		Entry("absolute member name", extractMember{name: "/evil", typeflag: tar.TypeReg, mode: 0o644, body: "x"}),
		Entry("symlink escaping dest", extractMember{name: "app-1.0/escape", typeflag: tar.TypeSymlink, linkname: "../../../evil"}),
		Entry("absolute symlink target", extractMember{name: "app-1.0/abs", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}),
		Entry("hardlink", extractMember{name: "app-1.0/hard", typeflag: tar.TypeLink, linkname: "app-1.0/bin/app"}),
		Entry("FIFO", extractMember{name: "app-1.0/fifo", typeflag: tar.TypeFifo, mode: 0o644}),
		Entry("character device", extractMember{name: "app-1.0/null", typeflag: tar.TypeChar, mode: 0o644}),
		Entry("duplicate member", extractMember{name: "app-1.0/bin/app", typeflag: tar.TypeReg, mode: 0o755, body: "second"}),
	)
})

var _ = Describe("HashInstallSource", func() {
	It("refuses a FIFO without blocking on it", func() {
		pkgRoot := GinkgoT().TempDir()
		fifo := filepath.Join(pkgRoot, "pipe")
		Expect(syscall.Mkfifo(fifo, 0o644)).To(Succeed())

		done := make(chan error, 1)
		go func() {
			_, err := HashInstallSource(pkgRoot, fifo)
			done <- err
		}()
		var err error
		Eventually(done, "5s").Should(Receive(&err), "opening a FIFO would block until a writer appears")
		Expect(err).To(MatchError(ContainSubstring("is not a regular file")))
	})
})

var _ = Describe("CheckStripComponents", func() {
	DescribeTable("accepts a whole number from 0 to the member depth cap",
		func(v any, want int) {
			n, err := CheckStripComponents(v)
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(want))
		},
		Entry("zero", 0, 0),
		Entry("an int64", int64(3), 3),
		Entry("a whole float", 2.0, 2),
		Entry("a numeric string", "4", 4),
		Entry("the cap", 64, 64),
	)

	DescribeTable("refuses anything else",
		func(v any, want string) {
			_, err := CheckStripComponents(v)
			Expect(err).To(MatchError(want))
		},
		Entry("a negative int", -1, "must be a non-negative integer, got -1"),
		Entry("a negative string", "-2", "must be a non-negative integer, got -2"),
		Entry("a fraction", 1.5, "must be a non-negative integer, got 1.5"),
		Entry("a word", "one", "must be a non-negative integer, got one"),
		Entry("a bool", true, "must be a non-negative integer, got true"),
		Entry("one past the cap", 65, "must be at most 64, the deepest member path an archive may hold; got 65"),
		Entry("a float too large for an int", 1e300, "must be at most 64, the deepest member path an archive may hold; got 1e+300"),
		Entry("a huge numeric string", "99999999999999999999", "must be a non-negative integer, got 99999999999999999999"),
	)
})

var _ = Describe("CheckIncludePattern", func() {
	It("accepts a valid pattern", func() {
		Expect(CheckIncludePattern("bin/*")).To(Succeed())
	})

	It("refuses an empty pattern", func() {
		Expect(CheckIncludePattern("")).To(MatchError("has an empty pattern, which can match no archive member"))
	})

	It("refuses a malformed pattern", func() {
		Expect(CheckIncludePattern("bin/[")).To(MatchError(`pattern "bin/[" is not a valid path.Match pattern: syntax error in pattern`))
	})
})
