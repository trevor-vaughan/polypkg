package conflict_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/conflict"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func entry(path, pkg, action string) schema.OwnershipEntry {
	return schema.OwnershipEntry{Path: path, Package: pkg, Action: action}
}

var _ = Describe("Detect", func() {
	It("returns nothing for an empty set", func() {
		Expect(conflict.Detect(nil)).To(BeEmpty())
	})

	It("does not flag distinct shared paths", func() {
		got := conflict.Detect([]schema.OwnershipEntry{
			entry("bin/foo", "a", "path"),
			entry("bin/bar", "b", "path"),
		})
		Expect(got).To(BeEmpty())
	})

	It("flags one shared path claimed by two packages", func() {
		got := conflict.Detect([]schema.OwnershipEntry{
			entry("bin/foo", "b", "path"),
			entry("bin/foo", "a", "path"),
		})
		Expect(got).To(HaveLen(1))
		Expect(got[0].Path).To(Equal("bin/foo"))
		Expect(got[0].Packages).To(Equal([]string{"a", "b"})) // sorted
	})

	It("flags a 3-package conflict", func() {
		got := conflict.Detect([]schema.OwnershipEntry{
			entry("bin/foo", "c", "path"),
			entry("bin/foo", "a", "path"),
			entry("bin/foo", "b", "path"),
		})
		Expect(got).To(HaveLen(1))
		Expect(got[0].Packages).To(Equal([]string{"a", "b", "c"}))
	})

	It("never flags namespaced paths (they embed the package name)", func() {
		got := conflict.Detect([]schema.OwnershipEntry{
			entry("a/etc/conf", "a", "install"),
			entry("b/etc/conf", "b", "install"),
		})
		Expect(got).To(BeEmpty())
	})

	It("allows one package's multiple entries on the same path", func() {
		got := conflict.Detect([]schema.OwnershipEntry{
			entry("a/dir", "a", "dir"),
			entry("a/dir", "a", "perms"),
		})
		Expect(got).To(BeEmpty())
	})

	It("sorts multiple conflicts by path", func() {
		got := conflict.Detect([]schema.OwnershipEntry{
			entry("bin/z", "a", "path"), entry("bin/z", "b", "path"),
			entry("bin/a", "a", "path"), entry("bin/a", "b", "path"),
		})
		Expect(got).To(HaveLen(2))
		Expect(got[0].Path).To(Equal("bin/a"))
		Expect(got[1].Path).To(Equal("bin/z"))
	})

})

var _ = Describe("Detect action-awareness", func() {
	It("does not flag an all-alternatives group", func() {
		got := conflict.Detect([]schema.OwnershipEntry{
			entry("bin/editor", "vim", "alternatives"),
			entry("bin/editor", "neovim", "alternatives"),
		})
		Expect(got).To(BeEmpty())
	})

	It("flags two path claimants (unchanged)", func() {
		got := conflict.Detect([]schema.OwnershipEntry{
			entry("bin/foo", "a", "path"),
			entry("bin/foo", "b", "path"),
		})
		Expect(got).To(HaveLen(1))
	})

	It("flags a mixed path + alternatives group", func() {
		got := conflict.Detect([]schema.OwnershipEntry{
			entry("bin/editor", "a", "path"),
			entry("bin/editor", "b", "alternatives"),
		})
		Expect(got).To(HaveLen(1))
		Expect(got[0].Path).To(Equal("bin/editor"))
		Expect(got[0].Packages).To(Equal([]string{"a", "b"}))
	})
})

func follower(path, pkg, master string) schema.OwnershipEntry {
	return schema.OwnershipEntry{Path: path, Package: pkg, Action: "alternatives",
		Expected: schema.Expected{Master: master}}
}

var _ = Describe("Detect followers", func() {
	It("does not flag same-path followers that share a master", func() {
		got := conflict.Detect([]schema.OwnershipEntry{
			follower("man/man1/editor.1", "vim", "editor"),
			follower("man/man1/editor.1", "neovim", "editor"),
		})
		Expect(got).To(BeEmpty())
	})

	It("flags same-path followers with different masters", func() {
		got := conflict.Detect([]schema.OwnershipEntry{
			follower("man/man1/foo.1", "a", "editor"),
			follower("man/man1/foo.1", "b", "pager"),
		})
		Expect(got).To(HaveLen(1))
		Expect(got[0].Path).To(Equal("man/man1/foo.1"))
	})

	It("flags a primary and a follower claiming the same path", func() {
		got := conflict.Detect([]schema.OwnershipEntry{
			entry("bin/vi", "vim", "alternatives"), // primary named vi (Master == "")
			follower("bin/vi", "neovim", "editor"), // follower bin/vi of editor
		})
		Expect(got).To(HaveLen(1))
		Expect(got[0].Path).To(Equal("bin/vi"))
	})
})

var _ = Describe("Summary", func() {
	It("renders path and claimants exactly", func() {
		s := conflict.Summary([]conflict.Conflict{{Path: "bin/foo", Packages: []string{"a", "b"}}})
		Expect(s).To(Equal("bin/foo (claimed by a, b)"))
	})

	It("renders empty for no conflicts", func() {
		Expect(conflict.Summary(nil)).To(Equal(""))
	})

	It("joins multiple conflicts with a semicolon", func() {
		s := conflict.Summary([]conflict.Conflict{
			{Path: "bin/a", Packages: []string{"x", "y"}},
			{Path: "bin/b", Packages: []string{"y", "z"}},
		})
		Expect(s).To(Equal("bin/a (claimed by x, y); bin/b (claimed by y, z)"))
	})
})
