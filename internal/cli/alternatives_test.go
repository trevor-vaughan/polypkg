package cli

import (
	"errors"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/alternatives"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func altOwnEntry(name, pkg, source string, prio int) schema.OwnershipEntry {
	return schema.OwnershipEntry{
		Path: "bin/" + name, Package: pkg, Action: "alternatives",
		Expected: schema.Expected{FileType: "symlink", Target: source, Priority: prio},
	}
}

var _ = Describe("buildAltViews", func() {
	entries := []schema.OwnershipEntry{
		altOwnEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
		altOwnEntry("editor", "vim", "/a/vim/bin/vim", 10),
		altOwnEntry("pager", "less", "/a/less/bin/less", 5),
		{Path: "bin/other", Package: "p", Action: "path", Expected: schema.Expected{FileType: "symlink", Target: "/a/p/bin/other"}},
	}

	It("reports auto winner, mode auto, and providers sorted by priority desc", func() {
		views := buildAltViews(entries, nil)
		Expect(views).To(HaveLen(2)) // editor, pager — path entry ignored
		editor := views[0]
		Expect(editor.Name).To(Equal("editor"))
		Expect(editor.Winner).To(Equal("neovim"))
		Expect(editor.Priority).To(Equal(30))
		Expect(editor.Mode).To(Equal("auto"))
		Expect(editor.Providers[0].Package).To(Equal("neovim")) // highest first
		Expect(editor.Providers[1].Package).To(Equal("vim"))
	})

	It("reports mode manual when a valid selection chose the winner", func() {
		views := buildAltViews(entries, alternatives.Selections{"editor": "vim"})
		Expect(views[0].Winner).To(Equal("vim"))
		Expect(views[0].Mode).To(Equal("manual"))
		Expect(views[0].Stale).To(BeFalse())
		Expect(views[0].Priority).To(Equal(10))
		Expect(views[0].Source).To(Equal("/a/vim/bin/vim"))
	})

	It("marks a stale selection and falls back to auto", func() {
		views := buildAltViews(entries, alternatives.Selections{"editor": "emacs"})
		Expect(views[0].Winner).To(Equal("neovim")) // auto fallback
		Expect(views[0].Mode).To(Equal("auto"))
		Expect(views[0].Stale).To(BeTrue())
	})
})

var _ = Describe("validateAltSet", func() {
	entries := []schema.OwnershipEntry{
		altOwnEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
		altOwnEntry("editor", "vim", "/a/vim/bin/vim", 10),
	}

	It("accepts a current provider of a known alternative", func() {
		src, err := validateAltSet(entries, "editor", "vim")
		Expect(err).NotTo(HaveOccurred())
		Expect(src).To(Equal("/a/vim/bin/vim"))
	})

	It("rejects an unknown alternative name and lists known names", func() {
		_, err := validateAltSet(entries, "browser", "firefox")
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError")
		Expect(cliErr.Msg).To(ContainSubstring("unknown alternative"))
		Expect(cliErr.Hint).To(ContainSubstring("editor"))
	})

	It("rejects a package that does not provide the alternative and lists providers", func() {
		_, err := validateAltSet(entries, "editor", "emacs")
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError")
		Expect(cliErr.Msg).To(ContainSubstring("does not provide"))
		Expect(cliErr.Hint).To(ContainSubstring("neovim"))
		Expect(cliErr.Hint).To(ContainSubstring("vim"))
	})
})

var _ = Describe("altNameKnown", func() {
	entries := []schema.OwnershipEntry{
		altOwnEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
	}
	It("reports a known alternative name", func() {
		Expect(altNameKnown(entries, "editor")).To(BeTrue())
	})
	It("reports an unknown name as false", func() {
		Expect(altNameKnown(entries, "pager")).To(BeFalse())
	})
})

var _ = Describe("alternatives invalid --scope error", func() {
	It("returns CLIError for an unrecognised scope", func() {
		dir := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
		root := NewRootCmd()
		root.SetArgs([]string{"alternatives", "list", "--scope", "bogus"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(ContainSubstring(`"bogus"`))
		Expect(cliErr.Hint).To(ContainSubstring("user or system"))
	})
})

var _ = Describe("alternatives list no-generation error", func() {
	It("returns CLIError with apply hint when no generation exists", func() {
		dir := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
		root := NewRootCmd()
		root.SetArgs([]string{"alternatives", "list"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(Equal("no generation has been applied yet"))
		Expect(cliErr.Hint).To(Equal("run `polypkg apply` first"))
	})
})

var _ = Describe("alternatives views with followers", func() {
	entries := []schema.OwnershipEntry{
		{Path: "bin/editor", Package: "neovim", Action: "alternatives",
			Expected: schema.Expected{FileType: "symlink", Target: "/a/neovim/bin/nvim", Priority: 30}},
		{Path: "bin/editor", Package: "vim", Action: "alternatives",
			Expected: schema.Expected{FileType: "symlink", Target: "/a/vim/bin/vim", Priority: 10}},
		{Path: "man/man1/editor.1", Package: "neovim", Action: "alternatives",
			Expected: schema.Expected{FileType: "symlink", Target: "/a/neovim/share/man/man1/nvim.1", Master: "editor"}},
	}

	It("lists only the primary name, not follower paths", func() {
		Expect(altNames(entries)).To(Equal([]string{"editor"}))
	})

	It("lists only primary providers", func() {
		Expect(altProviders(entries, "editor")).To(Equal([]string{"neovim", "vim"}))
	})

	It("attaches the winner's followers to the view", func() {
		views := buildAltViews(entries, alternatives.Selections{})
		Expect(views).To(HaveLen(1))
		Expect(views[0].Name).To(Equal("editor"))
		Expect(views[0].Followers).To(HaveKeyWithValue("man/man1/editor.1", "/a/neovim/share/man/man1/nvim.1"))
	})

	It("does not treat a bin follower as a selectable primary name", func() {
		withBinFollower := []schema.OwnershipEntry{
			{Path: "bin/editor", Package: "neovim", Action: "alternatives",
				Expected: schema.Expected{FileType: "symlink", Target: "/a/neovim/bin/nvim", Priority: 30}},
			{Path: "bin/vi", Package: "neovim", Action: "alternatives",
				Expected: schema.Expected{FileType: "symlink", Target: "/a/neovim/bin/nvim", Master: "editor"}},
		}
		// "bin/vi" strips to "vi" — but it is a follower, so it must not be a known
		// primary name, and `set vi <pkg>` must be rejected.
		Expect(altNameKnown(withBinFollower, "vi")).To(BeFalse())
		_, err := validateAltSet(withBinFollower, "vi", "neovim")
		Expect(err).To(HaveOccurred())
	})
})
