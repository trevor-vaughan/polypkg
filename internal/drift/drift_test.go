package drift

import (
	"os"
	"path/filepath"
	"testing"

	ginkgo "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/alternatives"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// setupTree creates activeRoot and the listed entries on disk so the inspector
// has something real to lstat. Each entry has Type ("file"|"symlink"|"dir") and
// optional Mode/Target/Content.
type fsEntry struct {
	Path    string // relative to activeRoot
	Type    string
	Mode    os.FileMode
	Target  string
	Content []byte
}

func setupTree(t testing.TB, entries ...fsEntry) string {
	t.Helper()
	g := NewWithT(t)
	root := filepath.Join(t.TempDir(), "active")
	g.Expect(os.MkdirAll(root, 0o755)).To(Succeed())
	for _, e := range entries {
		full := filepath.Join(root, e.Path)
		g.Expect(os.MkdirAll(filepath.Dir(full), 0o755)).To(Succeed())
		switch e.Type {
		case "file":
			g.Expect(os.WriteFile(full, e.Content, e.Mode)).To(Succeed())
		case "symlink":
			g.Expect(os.Symlink(e.Target, full)).To(Succeed())
		case "dir":
			g.Expect(os.MkdirAll(full, e.Mode)).To(Succeed())
			g.Expect(os.Chmod(full, e.Mode)).To(Succeed())
		}
	}
	return root
}

var _ = ginkgo.Describe("Inspect skips non-placement actions", func() {
	mkOwn := func() *schema.Ownership {
		return &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user", Entries: []schema.OwnershipEntry{
			{Path: "hello/var/run/app.sock", Package: "hello", Action: "unmanaged",
				Expected: schema.Expected{FileType: "ghost"}, DriftPolicy: "unmanaged"},
			{Path: "hello/var/lib/app", Package: "hello", Action: "state",
				Expected: schema.Expected{FileType: "state", Target: "/x"}, DriftPolicy: "state"},
		}}
	}

	ginkgo.It("never reports drift for ghost or state entries when their paths are absent", func() {
		dir := ginkgo.GinkgoT().TempDir()
		active := filepath.Join(dir, "active")
		Expect(os.MkdirAll(filepath.Join(active, "hello"), 0o755)).To(Succeed())
		// Neither entry path exists on disk: unmanaged creates nothing by design,
		// and a state active-tree symlink may have been removed. Absence must NOT
		// be reported as missing-drift for these never-checked actions.
		drifted, err := Inspect(mkOwn(), active)
		Expect(err).NotTo(HaveOccurred())
		Expect(drifted).To(BeEmpty())
	})

	ginkgo.It("never reports drift for ghost or state entries when a stray artifact exists at the path", func() {
		dir := ginkgo.GinkgoT().TempDir()
		active := filepath.Join(dir, "active")
		Expect(os.MkdirAll(filepath.Join(active, "hello", "var", "run"), 0o755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(active, "hello", "var", "lib"), 0o755)).To(Succeed())
		// An app-created socket file and an unexpected directory: still never drift.
		Expect(os.WriteFile(filepath.Join(active, "hello", "var", "run", "app.sock"), []byte("x"), 0o600)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(active, "hello", "var", "lib", "app"), 0o755)).To(Succeed())
		drifted, err := Inspect(mkOwn(), active)
		Expect(err).NotTo(HaveOccurred())
		Expect(drifted).To(BeEmpty())
	})
})

var _ = ginkgo.Describe("Inspect", func() {
	ginkgo.It("reports no drift when a dir matches expected mode", func() {
		t := ginkgo.GinkgoTB()
		root := setupTree(t, fsEntry{Path: "hello/bin", Type: "dir", Mode: 0o755})
		prior := &schema.Ownership{Entries: []schema.OwnershipEntry{
			{Path: "hello/bin", Action: "dir", Expected: schema.Expected{FileType: "dir", Mode: "0755"}},
		}}
		got, err := Inspect(prior, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeEmpty())
	})

	ginkgo.It("reports ReasonMissing when an expected dir is absent", func() {
		t := ginkgo.GinkgoTB()
		root := setupTree(t)
		prior := &schema.Ownership{Entries: []schema.OwnershipEntry{
			{Path: "hello/bin", Action: "dir", Expected: schema.Expected{FileType: "dir", Mode: "0755"}},
		}}
		got, err := Inspect(prior, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].Reason).To(Equal(ReasonMissing))
		Expect(got[0].Observed).To(Equal("absent"))
	})

	ginkgo.It("reports ReasonMode when a dir's mode has changed", func() {
		t := ginkgo.GinkgoTB()
		root := setupTree(t, fsEntry{Path: "hello/bin", Type: "dir", Mode: 0o700})
		prior := &schema.Ownership{Entries: []schema.OwnershipEntry{
			{Path: "hello/bin", Action: "dir", Expected: schema.Expected{FileType: "dir", Mode: "0755"}},
		}}
		got, err := Inspect(prior, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].Reason).To(Equal(ReasonMode))
		Expect(got[0].Observed).To(Equal("0700"))
	})

	ginkgo.It("reports ReasonFileType when a dir has become a regular file", func() {
		t := ginkgo.GinkgoTB()
		root := setupTree(t, fsEntry{Path: "hello/bin", Type: "file", Mode: 0o644, Content: []byte("x")})
		prior := &schema.Ownership{Entries: []schema.OwnershipEntry{
			{Path: "hello/bin", Action: "dir", Expected: schema.Expected{FileType: "dir", Mode: "0755"}},
		}}
		got, err := Inspect(prior, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].Reason).To(Equal(ReasonFileType))
		Expect(got[0].Observed).To(Equal("regular"))
	})

	ginkgo.It("reports ReasonMode for a perms action when the mode has changed", func() {
		t := ginkgo.GinkgoTB()
		root := setupTree(t, fsEntry{Path: "hello/bin", Type: "dir", Mode: 0o700})
		prior := &schema.Ownership{Entries: []schema.OwnershipEntry{
			{Path: "hello/bin", Action: "perms", Expected: schema.Expected{Mode: "0755"}},
		}}
		got, err := Inspect(prior, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].Reason).To(Equal(ReasonMode))
	})

	ginkgo.It("reports ReasonTarget when a symlink target has changed", func() {
		t := ginkgo.GinkgoTB()
		root := setupTree(t, fsEntry{Path: "hello/link", Type: "symlink", Target: "bin/now"})
		prior := &schema.Ownership{Entries: []schema.OwnershipEntry{
			{Path: "hello/link", Action: "symlink", Expected: schema.Expected{FileType: "symlink", Target: "bin/then"}},
		}}
		got, err := Inspect(prior, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].Reason).To(Equal(ReasonTarget))
		Expect(got[0].Observed).To(Equal("bin/now"))
	})

	ginkgo.It("reports ReasonFileType when an expected symlink is a regular file", func() {
		t := ginkgo.GinkgoTB()
		root := setupTree(t, fsEntry{Path: "hello/link", Type: "file", Mode: 0o644, Content: []byte("x")})
		prior := &schema.Ownership{Entries: []schema.OwnershipEntry{
			{Path: "hello/link", Action: "symlink", Expected: schema.Expected{FileType: "symlink", Target: "bin/then"}},
		}}
		got, err := Inspect(prior, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].Reason).To(Equal(ReasonFileType))
	})

	ginkgo.It("returns nil or empty when the prior ownership is nil or empty", func() {
		t := ginkgo.GinkgoTB()
		root := setupTree(t)
		got, err := Inspect(nil, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeNil())
		got, err = Inspect(&schema.Ownership{}, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeEmpty())
	})
})

var _ = ginkgo.Describe("Inspect path action entries as symlinks", func() {
	ginkgo.It("reports target drift for a path entry whose symlink points elsewhere", func() {
		t := ginkgo.GinkgoTB()
		// On-disk link points at /other; recorded target is /want.
		active := setupTree(t, fsEntry{Path: "bin/foo", Type: "symlink", Target: "/other"})
		own := &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user", Entries: []schema.OwnershipEntry{
			{Path: "bin/foo", Package: "hello", Action: "path",
				Expected: schema.Expected{FileType: "symlink", Target: "/want"}},
		}}
		drifted, err := Inspect(own, active)
		Expect(err).NotTo(HaveOccurred())
		Expect(drifted).To(HaveLen(1))
		Expect(drifted[0].Reason).To(Equal(ReasonTarget))
		Expect(drifted[0].Observed).To(Equal("/other"))
	})

	ginkgo.It("reports no drift when the path symlink matches", func() {
		t := ginkgo.GinkgoTB()
		active := setupTree(t, fsEntry{Path: "bin/foo", Type: "symlink", Target: "/want"})
		own := &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user", Entries: []schema.OwnershipEntry{
			{Path: "bin/foo", Package: "hello", Action: "path",
				Expected: schema.Expected{FileType: "symlink", Target: "/want"}},
		}}
		drifted, err := Inspect(own, active)
		Expect(err).NotTo(HaveOccurred())
		Expect(drifted).To(BeEmpty())
	})
})

var _ = ginkgo.Describe("InspectAlternatives", func() {
	setup := func() (active, altRoot string, own *schema.Ownership) {
		dir := ginkgo.GinkgoT().TempDir()
		active = filepath.Join(dir, "active")
		altRoot = filepath.Join(dir, "alternatives")
		Expect(os.MkdirAll(filepath.Join(active, "bin"), 0o755)).To(Succeed())
		Expect(os.MkdirAll(altRoot, 0o755)).To(Succeed())
		// winner is neovim (priority 30)
		Expect(os.Symlink(filepath.Join(altRoot, "editor"), filepath.Join(active, "bin", "editor"))).To(Succeed())
		Expect(os.Symlink("/a/neovim/bin/nvim", filepath.Join(altRoot, "editor"))).To(Succeed())
		own = &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user", Entries: []schema.OwnershipEntry{
			{Path: "bin/editor", Package: "vim", Action: "alternatives",
				Expected: schema.Expected{FileType: "symlink", Target: "/a/vim/bin/vim", Priority: 10}},
			{Path: "bin/editor", Package: "neovim", Action: "alternatives",
				Expected: schema.Expected{FileType: "symlink", Target: "/a/neovim/bin/nvim", Priority: 30}},
		}}
		return
	}

	ginkgo.It("reports no drift when both link levels match the arbitrated winner", func() {
		active, altRoot, own := setup()
		got, err := InspectAlternatives(own, active, altRoot, filepath.Join(ginkgo.GinkgoT().TempDir(), "sel.json"))
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeEmpty())
	})

	ginkgo.It("reports target drift when the middle link points at the wrong source", func() {
		active, altRoot, own := setup()
		Expect(os.Remove(filepath.Join(altRoot, "editor"))).To(Succeed())
		Expect(os.Symlink("/a/vim/bin/vim", filepath.Join(altRoot, "editor"))).To(Succeed()) // wrong winner
		got, err := InspectAlternatives(own, active, altRoot, filepath.Join(ginkgo.GinkgoT().TempDir(), "sel.json"))
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(string(got[0].Reason)).To(Equal("target"))
	})

	ginkgo.It("reports target drift when the consumer link is repointed away from the middle link", func() {
		active, altRoot, own := setup()
		Expect(os.Remove(filepath.Join(active, "bin", "editor"))).To(Succeed())
		Expect(os.Symlink("/somewhere/else", filepath.Join(active, "bin", "editor"))).To(Succeed())
		got, err := InspectAlternatives(own, active, altRoot, filepath.Join(ginkgo.GinkgoT().TempDir(), "sel.json"))
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(string(got[0].Reason)).To(Equal("target"))
	})

	ginkgo.It("reports target drift when a follower middle link points at the wrong source", func() {
		dir := ginkgo.GinkgoT().TempDir()
		active := filepath.Join(dir, "active")
		altRoot := filepath.Join(dir, "alternatives")
		Expect(os.MkdirAll(filepath.Join(active, "man", "man1"), 0o755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(altRoot, ".followers", "man", "man1"), 0o755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(active, "bin"), 0o755)).To(Succeed())
		// primary editor -> neovim (correct, so only the follower drifts)
		Expect(os.Symlink(filepath.Join(altRoot, "editor"), filepath.Join(active, "bin", "editor"))).To(Succeed())
		Expect(os.Symlink("/a/neovim/bin/nvim", filepath.Join(altRoot, "editor"))).To(Succeed())
		// follower consumer link (correct) -> .followers/man/man1/editor.1
		Expect(os.Symlink(filepath.Join(altRoot, ".followers", "man", "man1", "editor.1"),
			filepath.Join(active, "man", "man1", "editor.1"))).To(Succeed())
		// follower middle link points at the WRONG source
		Expect(os.Symlink("/a/vim/share/man/man1/vim.1",
			filepath.Join(altRoot, ".followers", "man", "man1", "editor.1"))).To(Succeed())

		own := &schema.Ownership{Entries: []schema.OwnershipEntry{
			{Path: "bin/editor", Package: "neovim", Action: "alternatives",
				Expected: schema.Expected{FileType: "symlink", Target: "/a/neovim/bin/nvim", Priority: 30}},
			{Path: "man/man1/editor.1", Package: "neovim", Action: "alternatives",
				Expected: schema.Expected{FileType: "symlink", Target: "/a/neovim/share/man/man1/nvim.1", Master: "editor"}},
		}}
		got, err := InspectAlternatives(own, active, altRoot, filepath.Join(ginkgo.GinkgoT().TempDir(), "sel.json"))
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].Reason).To(Equal(ReasonTarget))
		Expect(got[0].Owned.Path).To(Equal("man/man1/editor.1"))
	})

	ginkgo.It("reports target drift when a follower consumer link is repointed away from .followers", func() {
		dir := ginkgo.GinkgoT().TempDir()
		active := filepath.Join(dir, "active")
		altRoot := filepath.Join(dir, "alternatives")
		Expect(os.MkdirAll(filepath.Join(active, "man", "man1"), 0o755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(altRoot, ".followers", "man", "man1"), 0o755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(active, "bin"), 0o755)).To(Succeed())
		// primary editor -> neovim (correct, so only the follower drifts)
		Expect(os.Symlink(filepath.Join(altRoot, "editor"), filepath.Join(active, "bin", "editor"))).To(Succeed())
		Expect(os.Symlink("/a/neovim/bin/nvim", filepath.Join(altRoot, "editor"))).To(Succeed())
		// follower middle link is correct...
		Expect(os.Symlink("/a/neovim/share/man/man1/nvim.1",
			filepath.Join(altRoot, ".followers", "man", "man1", "editor.1"))).To(Succeed())
		// ...but the follower CONSUMER link is repointed somewhere other than .followers
		Expect(os.Symlink("/somewhere/else",
			filepath.Join(active, "man", "man1", "editor.1"))).To(Succeed())

		own := &schema.Ownership{Entries: []schema.OwnershipEntry{
			{Path: "bin/editor", Package: "neovim", Action: "alternatives",
				Expected: schema.Expected{FileType: "symlink", Target: "/a/neovim/bin/nvim", Priority: 30}},
			{Path: "man/man1/editor.1", Package: "neovim", Action: "alternatives",
				Expected: schema.Expected{FileType: "symlink", Target: "/a/neovim/share/man/man1/nvim.1", Master: "editor"}},
		}}
		got, err := InspectAlternatives(own, active, altRoot, filepath.Join(ginkgo.GinkgoT().TempDir(), "sel.json"))
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].Reason).To(Equal(ReasonTarget))
		Expect(got[0].Owned.Path).To(Equal("man/man1/editor.1"))
		Expect(got[0].Observed).To(Equal("/somewhere/else"))
	})

	ginkgo.It("expects the selected provider's source, not the auto winner", func() {
		// The setup() helper creates links for the auto winner (neovim, priority 30).
		// We override the selection to vim (priority 10) and rebuild the links to
		// match, then verify InspectAlternatives reports no drift.
		active, altRoot, own := setup()

		dir := ginkgo.GinkgoT().TempDir()
		selPath := filepath.Join(dir, "sel.json")
		Expect(alternatives.SaveSelections(selPath, alternatives.Selections{"editor": "vim"})).To(Succeed())

		// Rebuild the middle link to point at the selected (vim) source.
		Expect(os.Remove(filepath.Join(altRoot, "editor"))).To(Succeed())
		Expect(os.Symlink("/a/vim/bin/vim", filepath.Join(altRoot, "editor"))).To(Succeed())
		// Consumer link already points at altRoot/editor (created by setup); leave it.

		drifted, err := InspectAlternatives(own, active, altRoot, selPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(drifted).To(BeEmpty())
	})
})

var _ = ginkgo.Describe("Inspect skips alternatives registration entries", func() {
	ginkgo.It("does not flag an alternatives entry via per-entry inspection", func() {
		dir := ginkgo.GinkgoT().TempDir()
		active := filepath.Join(dir, "active")
		Expect(os.MkdirAll(filepath.Join(active, "bin"), 0o755)).To(Succeed())
		own := &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user", Entries: []schema.OwnershipEntry{
			{Path: "bin/editor", Package: "neovim", Action: "alternatives",
				Expected: schema.Expected{FileType: "symlink", Target: "/a/neovim/bin/nvim", Priority: 30}},
		}}
		got, err := Inspect(own, active)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeEmpty()) // per-entry inspection skips alternatives
	})
})
