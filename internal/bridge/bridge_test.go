package bridge_test

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/bridge"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func dirs(cmds ...string) (binDir, activeBinDir string) {
	binDir = GinkgoT().TempDir()
	activeBinDir = filepath.Join(GinkgoT().TempDir(), "active", "bin")
	Expect(os.MkdirAll(activeBinDir, 0o755)).To(Succeed())
	for _, c := range cmds {
		Expect(os.WriteFile(filepath.Join(activeBinDir, c), []byte("#!/bin/sh\n"), 0o755)).To(Succeed())
	}
	return binDir, activeBinDir
}

var _ = Describe("ExposedCommands", func() {
	It("selects path and alternatives bin/<name> entries, sorted unique", func() {
		entries := []schema.OwnershipEntry{
			{Path: "bin/rg", Action: "path"},
			{Path: "bin/editor", Action: "alternatives"},
			{Path: "bin/editor", Action: "alternatives"},
			{Path: "hello/etc/x.conf", Action: "config"},
			{Path: "bin/keep", Action: "install"},
		}
		Expect(bridge.ExposedCommands(entries)).To(Equal([]string{"editor", "rg"}))
	})
})

var _ = Describe("Reconcile", func() {
	It("links a new command to the stable active/bin target", func() {
		binDir, active := dirs("rg")
		res, err := bridge.Reconcile(binDir, active, []string{"rg"})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Linked).To(Equal([]string{"rg"}))
		tgt, _ := os.Readlink(filepath.Join(binDir, "rg"))
		Expect(tgt).To(Equal(filepath.Join(active, "rg")))
	})

	It("is idempotent — an already-correct ours-link is a no-op", func() {
		binDir, active := dirs("rg")
		_, err := bridge.Reconcile(binDir, active, []string{"rg"})
		Expect(err).NotTo(HaveOccurred())
		res, err := bridge.Reconcile(binDir, active, []string{"rg"})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Linked).To(BeEmpty())
		Expect(res.Pruned).To(BeEmpty())
	})

	It("repoints a stale ours-link to the correct target", func() {
		binDir, active := dirs("rg")
		// An ours-link (points into active/bin) but at the wrong slot.
		Expect(os.Symlink(filepath.Join(active, "stale"), filepath.Join(binDir, "rg"))).To(Succeed())
		res, err := bridge.Reconcile(binDir, active, []string{"rg"})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Linked).To(Equal([]string{"rg"}))
		Expect(res.Skipped).To(BeEmpty())
		tgt, _ := os.Readlink(filepath.Join(binDir, "rg"))
		Expect(tgt).To(Equal(filepath.Join(active, "rg")))
	})

	It("filters malformed names out of ExposedCommands", func() {
		entries := []schema.OwnershipEntry{
			{Path: "bin/", Action: "path"},        // empty name
			{Path: "bin/sub/cmd", Action: "path"}, // contains a slash
			{Path: "bin/ok", Action: "alternatives"},
		}
		Expect(bridge.ExposedCommands(entries)).To(Equal([]string{"ok"}))
	})

	It("prunes an ours-link whose command is no longer wanted", func() {
		binDir, active := dirs("rg", "fd")
		_, err := bridge.Reconcile(binDir, active, []string{"rg", "fd"})
		Expect(err).NotTo(HaveOccurred())
		res, err := bridge.Reconcile(binDir, active, []string{"rg"})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Pruned).To(Equal([]string{"fd"}))
		_, statErr := os.Lstat(filepath.Join(binDir, "fd"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
	})

	It("skips and reports a foreign regular file, never overwriting it", func() {
		binDir, active := dirs("rg")
		foreign := filepath.Join(binDir, "rg")
		Expect(os.WriteFile(foreign, []byte("my own script"), 0o755)).To(Succeed())
		res, err := bridge.Reconcile(binDir, active, []string{"rg"})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Linked).To(BeEmpty())
		Expect(res.Skipped).To(HaveLen(1))
		Expect(res.Skipped[0].Name).To(Equal("rg"))
		data, _ := os.ReadFile(foreign)
		Expect(string(data)).To(Equal("my own script"))
	})

	It("skips and reports a foreign symlink (target outside active/bin)", func() {
		binDir, active := dirs("rg")
		Expect(os.Symlink("/usr/bin/rg", filepath.Join(binDir, "rg"))).To(Succeed())
		res, err := bridge.Reconcile(binDir, active, []string{"rg"})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Skipped).To(HaveLen(1))
		tgt, _ := os.Readlink(filepath.Join(binDir, "rg"))
		Expect(tgt).To(Equal("/usr/bin/rg"))
	})

	It("does not prune a foreign symlink that happens to be unwanted", func() {
		binDir, active := dirs("rg")
		Expect(os.Symlink("/usr/bin/fd", filepath.Join(binDir, "fd"))).To(Succeed())
		res, err := bridge.Reconcile(binDir, active, []string{"rg"})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Pruned).To(BeEmpty())
		_, statErr := os.Lstat(filepath.Join(binDir, "fd"))
		Expect(statErr).NotTo(HaveOccurred())
	})

	It("rejects a non-component command name", func() {
		binDir, active := dirs()
		_, err := bridge.Reconcile(binDir, active, []string{"../evil"})
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("PruneAll", func() {
	It("removes only ours-links, leaving foreign entries", func() {
		binDir, active := dirs("rg")
		_, err := bridge.Reconcile(binDir, active, []string{"rg"})
		Expect(err).NotTo(HaveOccurred())
		Expect(os.Symlink("/usr/bin/fd", filepath.Join(binDir, "fd"))).To(Succeed())
		Expect(os.WriteFile(filepath.Join(binDir, "mine.sh"), []byte("x"), 0o755)).To(Succeed())
		pruned, err := bridge.PruneAll(binDir, active)
		Expect(err).NotTo(HaveOccurred())
		Expect(pruned).To(Equal([]string{"rg"}))
		_, e1 := os.Lstat(filepath.Join(binDir, "fd"))
		Expect(e1).NotTo(HaveOccurred())
		_, e2 := os.Lstat(filepath.Join(binDir, "mine.sh"))
		Expect(e2).NotTo(HaveOccurred())
	})

	It("returns no error when binDir does not exist", func() {
		pruned, err := bridge.PruneAll(filepath.Join(GinkgoT().TempDir(), "absent"), "/x/active/bin")
		Expect(err).NotTo(HaveOccurred())
		Expect(pruned).To(BeEmpty())
	})
})
