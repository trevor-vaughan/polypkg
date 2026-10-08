package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// writeCleanPkg materializes a minimal lint-clean package source (polypkg.yaml
// plus the referenced content stub) under dir, so `pkg lint` resolves PKG006.
func writeCleanPkg(dir string) {
	Expect(os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "content", "bin", "hello"),
		[]byte("#!/bin/sh\necho hello\n"), 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(`schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: dir
    params: { path: "$ACTIVE/hello" }
  - phase: post-place
    action: install
    params: { src: "$PKG/content/bin/hello", dest: "$ACTIVE/hello/bin/hello" }
`), 0o644)).To(Succeed())
}

// writeUnknownActionPkg materializes a source whose only action is unknown to the
// registry; the schema rejects it as PKG000, so lint reports an error-severity
// finding and the command exits non-zero.
func writeUnknownActionPkg(dir string) {
	Expect(os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(`schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: frobnicate
    params: { path: "$ACTIVE/hello" }
`), 0o644)).To(Succeed())
}

var _ = Describe("pkg lint command", func() {
	It("exits 0 and prints clean for a valid package", func() {
		dir := GinkgoT().TempDir()
		writeCleanPkg(dir)

		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"pkg", "lint", dir})

		Expect(root.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("clean"))
	})

	It("exits non-zero on error-severity findings", func() {
		dir := GinkgoT().TempDir()
		writeUnknownActionPkg(dir)

		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"pkg", "lint", dir})

		Expect(root.Execute()).ToNot(Succeed())
	})

	It("--sarif writes a canonical SARIF 2.1.0 document to stdout", func() {
		dir := GinkgoT().TempDir()
		writeCleanPkg(dir)

		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"pkg", "lint", "--sarif", dir})

		Expect(root.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring(`"version"`))
		Expect(out.String()).To(ContainSubstring("2.1.0"))
	})

	It("--sarif -o writes the SARIF to a file, not stdout", func() {
		dir := GinkgoT().TempDir()
		writeCleanPkg(dir)
		sink := filepath.Join(GinkgoT().TempDir(), "out.sarif")

		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"pkg", "lint", "--sarif", "-o", sink, dir})

		Expect(root.Execute()).To(Succeed())
		raw, err := os.ReadFile(sink)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring("2.1.0"))
		Expect(out.String()).ToNot(ContainSubstring("2.1.0"))
	})

	It("does not break the inherited global -f/--format shorthand", func() {
		dir := GinkgoT().TempDir()
		writeCleanPkg(dir)

		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"-f", "json", "pkg", "lint", dir})

		Expect(root.Execute()).To(Succeed())
	})

	It("refuses -o without --sarif instead of writing nothing", func() {
		dir := GinkgoT().TempDir()
		writeCleanPkg(dir)
		sink := filepath.Join(GinkgoT().TempDir(), "out.sarif")

		root := NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"pkg", "lint", "-o", sink, dir})

		err := root.Execute()
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(Equal("-o/--output needs --sarif"))
		Expect(ce.Hint).To(ContainSubstring("stderr under --format json"))
		Expect(sink).NotTo(BeAnExistingFile())
	})
})

var _ = Describe("pkg lint and pkg build on a directory that is not a package", func() {
	DescribeTable("say what is missing and how to make one",
		func(command string, makeDir func(string) string, wantMsg string) {
			dir := makeDir(GinkgoT().TempDir())
			root := NewRootCmd()
			root.SetOut(&bytes.Buffer{})
			root.SetErr(&bytes.Buffer{})
			args := []string{"pkg", command, dir}
			if command == "build" {
				args = append(args, "-o", GinkgoT().TempDir())
			}
			root.SetArgs(args)
			err := root.Execute()

			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(Equal(fmt.Sprintf(wantMsg, dir)))
			Expect(ce.Hint).To(ContainSubstring("polypkg.yaml"))
			Expect(ce.Hint).To(ContainSubstring("polypkg pkg init"))
		},
		Entry("lint, empty directory", "lint", func(d string) string { return d }, "%s has no polypkg.yaml"),
		Entry("build, empty directory", "build", func(d string) string { return d }, "%s has no polypkg.yaml"),
		Entry("lint, missing directory", "lint", func(d string) string { return filepath.Join(d, "nope") }, "package directory %s does not exist"),
		Entry("build, missing directory", "build", func(d string) string { return filepath.Join(d, "nope") }, "package directory %s does not exist"),
	)
})
