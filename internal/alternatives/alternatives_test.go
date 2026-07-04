package alternatives_test

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/alternatives"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// altEntry builds an alternatives provider-registration ownership entry.
func altEntry(name, pkg, source string, priority int) schema.OwnershipEntry {
	return schema.OwnershipEntry{
		Path: "bin/" + name, Package: pkg, Action: "alternatives",
		Expected: schema.Expected{FileType: "symlink", Target: source, Priority: priority},
	}
}

func followerEntry(master, pkg, link, source string) schema.OwnershipEntry {
	return schema.OwnershipEntry{
		Path: link, Package: pkg, Action: "alternatives",
		Expected: schema.Expected{FileType: "symlink", Target: source, Master: master},
	}
}

var _ = Describe("Arbitrate", func() {
	It("returns no winners for no alternatives entries", func() {
		Expect(alternatives.Arbitrate(nil)).To(BeEmpty())
	})

	It("picks the highest priority provider per name", func() {
		w := alternatives.Arbitrate([]schema.OwnershipEntry{
			altEntry("editor", "vim", "/a/vim/bin/vim", 20),
			altEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
			altEntry("editor", "nano", "/a/nano/bin/nano", 10),
		})
		Expect(w).To(HaveLen(1))
		Expect(w["editor"].Package).To(Equal("neovim"))
		Expect(w["editor"].Source).To(Equal("/a/neovim/bin/nvim"))
	})

	It("breaks ties by package name ascending", func() {
		w := alternatives.Arbitrate([]schema.OwnershipEntry{
			altEntry("editor", "vim", "/a/vim/bin/vim", 30),
			altEntry("editor", "emacs", "/a/emacs/bin/emacs", 30),
		})
		Expect(w["editor"].Package).To(Equal("emacs")) // tie -> lexicographically first
	})

	It("selects a sole provider", func() {
		w := alternatives.Arbitrate([]schema.OwnershipEntry{
			altEntry("pager", "less", "/a/less/bin/less", -5),
		})
		Expect(w["pager"].Package).To(Equal("less"))
		Expect(w["pager"].Source).To(Equal("/a/less/bin/less"))
	})

	It("orders negative priorities correctly", func() {
		w := alternatives.Arbitrate([]schema.OwnershipEntry{
			altEntry("x", "a", "/a/a/x", -10),
			altEntry("x", "b", "/a/b/x", -1),
		})
		Expect(w["x"].Package).To(Equal("b")) // -1 > -10
	})

	It("resolves multiple distinct names independently", func() {
		w := alternatives.Arbitrate([]schema.OwnershipEntry{
			altEntry("editor", "vim", "/a/vim/bin/vim", 10),
			altEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
			altEntry("pager", "less", "/a/less/bin/less", 5),
			altEntry("pager", "more", "/a/more/bin/more", 8),
		})
		Expect(w).To(HaveLen(2))
		Expect(w["editor"].Package).To(Equal("neovim"))
		Expect(w["pager"].Package).To(Equal("more"))
	})

	It("ignores non-alternatives entries", func() {
		w := alternatives.Arbitrate([]schema.OwnershipEntry{
			{Path: "bin/foo", Package: "p", Action: "path",
				Expected: schema.Expected{FileType: "symlink", Target: "/a/p/bin/foo"}},
		})
		Expect(w).To(BeEmpty())
	})
})

var _ = Describe("Reconcile (auto, migrated from Materialize)", func() {
	autoSel := func() string { return filepath.Join(GinkgoT().TempDir(), "absent.json") }

	It("creates a middle link to the winner's source", func() {
		altRoot := GinkgoT().TempDir()
		_, err := alternatives.Reconcile(altRoot, autoSel(), []schema.OwnershipEntry{
			altEntry("editor", "vim", "/a/vim/bin/vim", 20),
			altEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
		})
		Expect(err).NotTo(HaveOccurred())
		target, rerr := os.Readlink(filepath.Join(altRoot, "editor"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(target).To(Equal("/a/neovim/bin/nvim"))
	})

	It("updates an existing middle link to the new winner (idempotent reconcile)", func() {
		altRoot := GinkgoT().TempDir()
		Expect(os.Symlink("/old/target", filepath.Join(altRoot, "editor"))).To(Succeed())
		_, err := alternatives.Reconcile(altRoot, autoSel(), []schema.OwnershipEntry{
			altEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
		})
		Expect(err).NotTo(HaveOccurred())
		target, rerr := os.Readlink(filepath.Join(altRoot, "editor"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(target).To(Equal("/a/neovim/bin/nvim"))
	})

	It("prunes a middle link whose name has no current provider", func() {
		altRoot := GinkgoT().TempDir()
		Expect(os.Symlink("/gone/target", filepath.Join(altRoot, "pager"))).To(Succeed())
		_, err := alternatives.Reconcile(altRoot, autoSel(), []schema.OwnershipEntry{
			altEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
		})
		Expect(err).NotTo(HaveOccurred())
		_, statErr := os.Lstat(filepath.Join(altRoot, "pager"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
		_, statErr2 := os.Lstat(filepath.Join(altRoot, "editor"))
		Expect(statErr2).NotTo(HaveOccurred())
	})

	It("no-ops cleanly when there are no providers and no existing links", func() {
		altRoot := GinkgoT().TempDir()
		_, err := alternatives.Reconcile(altRoot, autoSel(), nil)
		Expect(err).NotTo(HaveOccurred())
	})
})

var _ = Describe("Resolve", func() {
	entries := []schema.OwnershipEntry{
		altEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
		altEntry("editor", "vim", "/a/vim/bin/vim", 10),
		altEntry("pager", "less", "/a/less/bin/less", 5),
	}

	It("equals Arbitrate when there are no selections", func() {
		w, stale := alternatives.Resolve(entries, nil)
		Expect(stale).To(BeEmpty())
		Expect(w["editor"].Package).To(Equal("neovim"))
		Expect(w["pager"].Package).To(Equal("less"))
	})

	It("lets a selection override a higher-priority auto winner", func() {
		w, stale := alternatives.Resolve(entries, alternatives.Selections{"editor": "vim"})
		Expect(stale).To(BeEmpty())
		Expect(w["editor"].Package).To(Equal("vim"))
		Expect(w["editor"].Source).To(Equal("/a/vim/bin/vim"))
	})

	It("reports a selection whose package is not a current provider as stale and falls back to auto", func() {
		w, stale := alternatives.Resolve(entries, alternatives.Selections{"editor": "emacs"})
		Expect(stale).To(ConsistOf("editor"))
		Expect(w["editor"].Package).To(Equal("neovim")) // auto fallback
	})

	It("reports a selection for a name with no providers as stale and contributes no winner", func() {
		w, stale := alternatives.Resolve(entries, alternatives.Selections{"browser": "firefox"})
		Expect(stale).To(ConsistOf("browser"))
		_, ok := w["browser"]
		Expect(ok).To(BeFalse())
	})

	It("does not mutate the passed selections map", func() {
		sel := alternatives.Selections{"editor": "emacs"}
		alternatives.Resolve(entries, sel)
		Expect(sel).To(Equal(alternatives.Selections{"editor": "emacs"}))
	})
})

var _ = Describe("Reconcile", func() {
	entries := []schema.OwnershipEntry{
		altEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
		altEntry("editor", "vim", "/a/vim/bin/vim", 10),
	}

	It("materializes the auto winner when there are no selections", func() {
		dir := GinkgoT().TempDir()
		altRoot := filepath.Join(dir, "alternatives")
		selPath := filepath.Join(dir, "state", alternatives.SelectionsFile)
		stale, err := alternatives.Reconcile(altRoot, selPath, entries)
		Expect(err).NotTo(HaveOccurred())
		Expect(stale).To(BeEmpty())
		tgt, _ := os.Readlink(filepath.Join(altRoot, "editor"))
		Expect(tgt).To(Equal("/a/neovim/bin/nvim"))
	})

	It("materializes the selected provider when a selection is present", func() {
		dir := GinkgoT().TempDir()
		altRoot := filepath.Join(dir, "alternatives")
		selPath := filepath.Join(dir, "state", alternatives.SelectionsFile)
		Expect(alternatives.SaveSelections(selPath, alternatives.Selections{"editor": "vim"})).To(Succeed())
		stale, err := alternatives.Reconcile(altRoot, selPath, entries)
		Expect(err).NotTo(HaveOccurred())
		Expect(stale).To(BeEmpty())
		tgt, _ := os.Readlink(filepath.Join(altRoot, "editor"))
		Expect(tgt).To(Equal("/a/vim/bin/vim"))
	})

	It("prunes a stale selection from the store, falls back to auto, and reports it", func() {
		dir := GinkgoT().TempDir()
		altRoot := filepath.Join(dir, "alternatives")
		selPath := filepath.Join(dir, "state", alternatives.SelectionsFile)
		Expect(alternatives.SaveSelections(selPath, alternatives.Selections{"editor": "emacs"})).To(Succeed())
		stale, err := alternatives.Reconcile(altRoot, selPath, entries)
		Expect(err).NotTo(HaveOccurred())
		Expect(stale).To(ConsistOf("editor"))
		tgt, _ := os.Readlink(filepath.Join(altRoot, "editor"))
		Expect(tgt).To(Equal("/a/neovim/bin/nvim")) // auto fallback
		sel, _ := alternatives.LoadSelections(selPath)
		Expect(sel).NotTo(HaveKey("editor")) // pruned and persisted
	})

	It("treats a missing selection store as empty selections", func() {
		dir := GinkgoT().TempDir()
		altRoot := filepath.Join(dir, "alternatives")
		selPath := filepath.Join(dir, "state", "absent.json")
		stale, err := alternatives.Reconcile(altRoot, selPath, entries)
		Expect(err).NotTo(HaveOccurred())
		Expect(stale).To(BeEmpty())
		tgt, _ := os.Readlink(filepath.Join(altRoot, "editor"))
		Expect(tgt).To(Equal("/a/neovim/bin/nvim"))
	})
})

var _ = Describe("materialize followers", func() {
	autoSel := func() string { return filepath.Join(GinkgoTB().TempDir(), "absent.json") }

	It("creates a follower middle link under .followers and resolves to the winner source", func() {
		altRoot := filepath.Join(GinkgoTB().TempDir(), "alternatives")
		entries := []schema.OwnershipEntry{
			altEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
			followerEntry("editor", "neovim", "man/man1/editor.1", "/a/neovim/share/man/man1/nvim.1"),
		}
		_, err := alternatives.Reconcile(altRoot, autoSel(), entries)
		Expect(err).NotTo(HaveOccurred())
		tgt, rerr := os.Readlink(filepath.Join(altRoot, ".followers", "man", "man1", "editor.1"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(tgt).To(Equal("/a/neovim/share/man/man1/nvim.1"))
	})

	It("prunes a follower middle link and its now-empty dirs when the winner no longer provides it", func() {
		altRoot := filepath.Join(GinkgoTB().TempDir(), "alternatives")
		_, err := alternatives.Reconcile(altRoot, autoSel(), []schema.OwnershipEntry{
			altEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
			followerEntry("editor", "neovim", "man/man1/editor.1", "/a/neovim/share/man/man1/nvim.1"),
		})
		Expect(err).NotTo(HaveOccurred())
		_, lstatErr := os.Lstat(filepath.Join(altRoot, ".followers", "man", "man1", "editor.1"))
		Expect(lstatErr).NotTo(HaveOccurred()) // symlink exists (may be dangling — target need not exist)
		_, err = alternatives.Reconcile(altRoot, autoSel(), []schema.OwnershipEntry{
			altEntry("editor", "vim", "/a/vim/bin/vim", 40),
		})
		Expect(err).NotTo(HaveOccurred())
		_, statErr := os.Lstat(filepath.Join(altRoot, ".followers", "man", "man1", "editor.1"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
		_, dirErr := os.Lstat(filepath.Join(altRoot, ".followers", "man", "man1"))
		Expect(os.IsNotExist(dirErr)).To(BeTrue())
	})

	It("does not prune the .followers tree during the top-level primary prune", func() {
		altRoot := filepath.Join(GinkgoTB().TempDir(), "alternatives")
		_, err := alternatives.Reconcile(altRoot, autoSel(), []schema.OwnershipEntry{
			altEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
			followerEntry("editor", "neovim", "bin/vi", "/a/neovim/bin/nvim"),
		})
		Expect(err).NotTo(HaveOccurred())
		_, lstatErr := os.Lstat(filepath.Join(altRoot, ".followers", "bin", "vi"))
		Expect(lstatErr).NotTo(HaveOccurred()) // symlink exists after first reconcile
		_, err = alternatives.Reconcile(altRoot, autoSel(), []schema.OwnershipEntry{
			altEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
			followerEntry("editor", "neovim", "bin/vi", "/a/neovim/bin/nvim"),
		})
		Expect(err).NotTo(HaveOccurred())
		_, lstatErr2 := os.Lstat(filepath.Join(altRoot, ".followers", "bin", "vi"))
		Expect(lstatErr2).NotTo(HaveOccurred()) // still present after idempotent second reconcile
	})

	It("prunes only the dropped follower's emptied dirs, keeping a live sibling dir", func() {
		altRoot := filepath.Join(GinkgoTB().TempDir(), "alternatives")
		// gen1: winner provides two man followers in different sections.
		_, err := alternatives.Reconcile(altRoot, autoSel(), []schema.OwnershipEntry{
			altEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
			followerEntry("editor", "neovim", "man/man1/editor.1", "/a/neovim/share/man/man1/nvim.1"),
			followerEntry("editor", "neovim", "man/man5/editor.5", "/a/neovim/share/man/man5/nvim.5"),
		})
		Expect(err).NotTo(HaveOccurred())
		// os.Lstat (not BeAnExistingFile/os.Stat): the follower targets are
		// deliberately dangling, so only the link itself is checked.
		_, l1 := os.Lstat(filepath.Join(altRoot, ".followers", "man", "man1", "editor.1"))
		Expect(l1).NotTo(HaveOccurred())
		_, l5 := os.Lstat(filepath.Join(altRoot, ".followers", "man", "man5", "editor.5"))
		Expect(l5).NotTo(HaveOccurred())
		// gen2: same winner, but it drops the man5 follower and keeps man1.
		_, err = alternatives.Reconcile(altRoot, autoSel(), []schema.OwnershipEntry{
			altEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
			followerEntry("editor", "neovim", "man/man1/editor.1", "/a/neovim/share/man/man1/nvim.1"),
		})
		Expect(err).NotTo(HaveOccurred())
		// man5 link and its now-empty dir are pruned...
		_, gone := os.Lstat(filepath.Join(altRoot, ".followers", "man", "man5", "editor.5"))
		Expect(os.IsNotExist(gone)).To(BeTrue())
		_, goneDir := os.Lstat(filepath.Join(altRoot, ".followers", "man", "man5"))
		Expect(os.IsNotExist(goneDir)).To(BeTrue())
		// ...while the live man1 sibling and the shared parent man/ survive.
		_, live := os.Lstat(filepath.Join(altRoot, ".followers", "man", "man1", "editor.1"))
		Expect(live).NotTo(HaveOccurred())
	})
})

var _ = Describe("Arbitrate followers", func() {
	It("attaches followers only from the winning package", func() {
		entries := []schema.OwnershipEntry{
			altEntry("editor", "vim", "/a/vim/bin/vim", 10),
			altEntry("editor", "neovim", "/a/neovim/bin/nvim", 30), // winner
			followerEntry("editor", "vim", "man/man1/editor.1", "/a/vim/share/man/man1/vim.1"),
			followerEntry("editor", "neovim", "man/man1/editor.1", "/a/neovim/share/man/man1/nvim.1"),
			followerEntry("editor", "neovim", "bin/vi", "/a/neovim/bin/nvim"),
		}
		w := alternatives.Arbitrate(entries)
		Expect(w["editor"].Package).To(Equal("neovim"))
		Expect(w["editor"].Followers).To(HaveKeyWithValue("man/man1/editor.1", "/a/neovim/share/man/man1/nvim.1"))
		Expect(w["editor"].Followers).To(HaveKeyWithValue("bin/vi", "/a/neovim/bin/nvim"))
		Expect(w["editor"].Followers).To(HaveLen(2)) // none of vim's followers leak in
	})

	It("does not treat a follower entry as a primary alternative", func() {
		entries := []schema.OwnershipEntry{
			altEntry("editor", "vim", "/a/vim/bin/vim", 10),
			followerEntry("editor", "vim", "man/man1/editor.1", "/a/vim/share/man/man1/vim.1"),
		}
		w := alternatives.Arbitrate(entries)
		Expect(w).To(HaveLen(1)) // only "editor", not a bogus "man/man1/editor.1"
		Expect(w).To(HaveKey("editor"))
	})

	It("tracks a manual selection's followers", func() {
		entries := []schema.OwnershipEntry{
			altEntry("editor", "vim", "/a/vim/bin/vim", 10),
			altEntry("editor", "neovim", "/a/neovim/bin/nvim", 30),
			followerEntry("editor", "vim", "bin/vi", "/a/vim/bin/vim"),
			followerEntry("editor", "neovim", "bin/vi", "/a/neovim/bin/nvim"),
		}
		w, stale := alternatives.Resolve(entries, alternatives.Selections{"editor": "vim"})
		Expect(stale).To(BeEmpty())
		Expect(w["editor"].Package).To(Equal("vim"))
		Expect(w["editor"].Followers).To(HaveKeyWithValue("bin/vi", "/a/vim/bin/vim"))
	})
})
