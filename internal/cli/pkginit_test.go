package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/pkglint"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("pkg init", func() {
	It("scaffolds a source that lints clean (round-trip invariant)", func() {
		dir := GinkgoT().TempDir()
		target := filepath.Join(dir, "hello")
		root := NewRootCmd()
		root.SetArgs([]string{"pkg", "init", target})
		Expect(root.Execute()).To(Succeed())

		Expect(filepath.Join(target, "polypkg.yaml")).To(BeAnExistingFile())
		Expect(filepath.Join(target, "content", "bin", "hello")).To(BeAnExistingFile())

		res, err := pkglint.Lint(target)
		Expect(err).ToNot(HaveOccurred())
		Expect(res.Findings).To(BeEmpty())

		// The scaffold hints at the optional title field via a YAML comment,
		// and the comment must not break the round-trip invariant above.
		raw, err := os.ReadFile(filepath.Join(target, "polypkg.yaml"))
		Expect(err).ToNot(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring("# title:"))
	})

	It("refuses to overwrite an existing polypkg.yaml without --force", func() {
		dir := GinkgoT().TempDir()
		Expect(os.MkdirAll(dir, 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte("x"), 0o644)).To(Succeed())
		root := NewRootCmd()
		root.SetArgs([]string{"pkg", "init", dir})
		Expect(root.Execute()).ToNot(Succeed())
	})

	It("overwrites an existing polypkg.yaml with --force", func() {
		dir := GinkgoT().TempDir()
		Expect(os.MkdirAll(dir, 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte("x"), 0o644)).To(Succeed())
		root := NewRootCmd()
		root.SetArgs([]string{"pkg", "init", "--force", dir})
		Expect(root.Execute()).To(Succeed())

		res, err := pkglint.Lint(dir)
		Expect(err).ToNot(HaveOccurred())
		Expect(res.Findings).To(BeEmpty())
	})

	It("defaults name to the directory basename", func() {
		dir := GinkgoT().TempDir()
		target := filepath.Join(dir, "foo")
		root := NewRootCmd()
		root.SetArgs([]string{"pkg", "init", target})
		Expect(root.Execute()).To(Succeed())

		pkg := parseScaffold(target)
		Expect(pkg.Name).To(Equal("foo"))
		Expect(pkg.Version).To(Equal("0.1.0"))
		Expect(filepath.Join(target, "content", "bin", "foo")).To(BeAnExistingFile())
	})

	It("rejects a non-slug basename and writes nothing to disk", func() {
		dir := GinkgoT().TempDir()
		target := filepath.Join(dir, "my.tool")
		root := NewRootCmd()
		root.SetArgs([]string{"pkg", "init", target})
		Expect(root.Execute()).ToNot(Succeed())

		Expect(filepath.Join(target, "polypkg.yaml")).ToNot(BeAnExistingFile())
		Expect(filepath.Join(target, "content")).ToNot(BeAnExistingFile())
	})

	It("accepts a valid --name override for a non-slug basename (round-trip)", func() {
		dir := GinkgoT().TempDir()
		target := filepath.Join(dir, "my.tool")
		root := NewRootCmd()
		root.SetArgs([]string{"pkg", "init", "--name", "mytool", target})
		Expect(root.Execute()).To(Succeed())

		pkg := parseScaffold(target)
		Expect(pkg.Name).To(Equal("mytool"))
		Expect(filepath.Join(target, "content", "bin", "mytool")).To(BeAnExistingFile())

		res, err := pkglint.Lint(target)
		Expect(err).ToNot(HaveOccurred())
		Expect(res.Findings).To(BeEmpty())
	})

	It("honors --name and --version overrides", func() {
		dir := GinkgoT().TempDir()
		target := filepath.Join(dir, "foo")
		root := NewRootCmd()
		root.SetArgs([]string{"pkg", "init", "--name", "bar", "--version", "2.0.0", target})
		Expect(root.Execute()).To(Succeed())

		pkg := parseScaffold(target)
		Expect(pkg.Name).To(Equal("bar"))
		Expect(pkg.Version).To(Equal("2.0.0"))
		Expect(filepath.Join(target, "content", "bin", "bar")).To(BeAnExistingFile())

		res, err := pkglint.Lint(target)
		Expect(err).ToNot(HaveOccurred())
		Expect(res.Findings).To(BeEmpty())
	})

	It("emits a task-first header that survives lint", func() {
		dir := GinkgoT().TempDir()
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"pkg", "init", "--name", "primerpkg", dir})
		Expect(cmd.Execute()).To(Succeed())

		raw, err := os.ReadFile(filepath.Join(dir, "polypkg.yaml"))
		Expect(err).NotTo(HaveOccurred())
		body := string(raw)

		// The header leads with the package identity and points at the
		// dedicated explain command instead of an inline primer wall.
		Expect(body).To(HavePrefix("# polypkg.yaml"))
		Expect(body).To(ContainSubstring("polypkg pkg explain"))
		Expect(body).To(ContainSubstring("content/bin"))
		Expect(body).To(ContainSubstring("phase:"))
		Expect(body).To(ContainSubstring("action:"))
		Expect(body).To(ContainSubstring("$PKG"))
		Expect(body).To(ContainSubstring("$ACTIVE"))
		// Header sits above the actions list, and the file still parses.
		Expect(strings.Index(body, "# polypkg.yaml")).
			To(BeNumerically("<", strings.Index(body, "actions:")))
		_, perr := schema.ParsePackage(bytes.NewReader(raw), "polypkg.yaml")
		Expect(perr).NotTo(HaveOccurred())
	})

	It("drops the redundant dir action and keeps install + path", func() {
		dir := GinkgoT().TempDir()
		target := filepath.Join(dir, "demo")
		root := NewRootCmd()
		root.SetArgs([]string{"pkg", "init", target})
		Expect(root.Execute()).To(Succeed())

		pkg := parseScaffold(target)
		var installs, paths int
		for _, a := range pkg.Actions {
			Expect(a.Action).NotTo(Equal("dir"))
			switch a.Action {
			case "install":
				installs++
				Expect(a.Params["src"]).To(Equal("$PKG/content/bin/" + pkg.Name))
				Expect(a.Params["dest"]).To(Equal("$ACTIVE/" + pkg.Name + "/bin/" + pkg.Name))
			case "path":
				paths++
			}
		}
		Expect(installs).To(Equal(1))
		Expect(paths).To(Equal(1))
	})

	It("scaffolds a clean hello-world stub", func() {
		dir := GinkgoT().TempDir()
		target := filepath.Join(dir, "demo")
		root := NewRootCmd()
		root.SetArgs([]string{"pkg", "init", target})
		Expect(root.Execute()).To(Succeed())

		stub, err := os.ReadFile(filepath.Join(target, "content", "bin", "demo"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(stub)).To(ContainSubstring("Hello, world!"))
		Expect(string(stub)).NotTo(ContainSubstring("hello from"))
	})

	It("exposes the stub command on PATH via the path action", func() {
		dir := GinkgoT().TempDir()
		target := filepath.Join(dir, "demo")
		root := NewRootCmd()
		root.SetArgs([]string{"pkg", "init", target})
		Expect(root.Execute()).To(Succeed())

		raw, err := os.ReadFile(filepath.Join(target, "polypkg.yaml"))
		Expect(err).NotTo(HaveOccurred())
		pkg, err := schema.ParsePackage(bytes.NewReader(raw), "polypkg.yaml")
		Expect(err).NotTo(HaveOccurred())
		var pathActions []schema.PackageAction
		for _, v := range pkg.Actions {
			if v.Action == "path" {
				pathActions = append(pathActions, v)
			}
		}
		Expect(pathActions).To(HaveLen(1))
		Expect(pathActions[0].Phase).To(Equal("post-place"))
		Expect(pathActions[0].Params["name"]).To(Equal(pkg.Name))
		Expect(pathActions[0].Params["source"]).To(Equal("$ACTIVE/" + pkg.Name + "/bin/" + pkg.Name))
	})
})

// parseScaffold reads and parses the scaffolded polypkg.yaml, failing the spec
// on any error.
func parseScaffold(dir string) *schema.Package {
	f, err := os.Open(filepath.Join(dir, "polypkg.yaml"))
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(f.Close)
	pkg, err := schema.ParsePackage(f, "polypkg.yaml")
	Expect(err).ToNot(HaveOccurred())
	return pkg
}
