package completion_test

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/completion"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("ExposedCompletions", func() {
	It("selects completion entries and parses shell + host file, dropping malformed", func() {
		entries := []schema.OwnershipEntry{
			{Path: "completions/bash/rg", Action: "completion"},
			{Path: "completions/zsh/_rg", Action: "completion"},
			{Path: "completions/fish/rg.fish", Action: "completion"},
			{Path: "bin/rg", Action: "path"},                     // not completion
			{Path: "completions/bash", Action: "completion"},     // malformed (no file)
			{Path: "completions/bash/a/b", Action: "completion"}, // malformed (extra segment)
		}
		got := completion.ExposedCompletions(entries)
		Expect(got).To(ConsistOf(
			completion.Want{Shell: "bash", HostFile: "rg"},
			completion.Want{Shell: "zsh", HostFile: "_rg"},
			completion.Want{Shell: "fish", HostFile: "rg.fish"},
		))
	})
})

var _ = Describe("Reconcile", func() {
	It("links each shell's host dir to the active completions area", func() {
		active := filepath.Join(GinkgoT().TempDir(), "active", "completions")
		for _, p := range []string{"bash/rg", "zsh/_rg", "fish/rg.fish"} {
			full := filepath.Join(active, p)
			Expect(os.MkdirAll(filepath.Dir(full), 0o750)).To(Succeed())
			Expect(os.WriteFile(full, []byte("comp"), 0o644)).To(Succeed())
		}
		hostDirs := map[string]string{
			"bash": GinkgoT().TempDir(),
			"zsh":  GinkgoT().TempDir(),
			"fish": GinkgoT().TempDir(),
		}
		want := []completion.Want{
			{Shell: "bash", HostFile: "rg"},
			{Shell: "zsh", HostFile: "_rg"},
			{Shell: "fish", HostFile: "rg.fish"},
		}
		res, err := completion.Reconcile(hostDirs, active, want)
		Expect(err).NotTo(HaveOccurred())
		Expect(res["bash"].Linked).To(Equal([]string{"rg"}))
		Expect(res["zsh"].Linked).To(Equal([]string{"_rg"}))
		Expect(res["fish"].Linked).To(Equal([]string{"rg.fish"}))
		tgt, _ := os.Readlink(filepath.Join(hostDirs["zsh"], "_rg"))
		Expect(tgt).To(Equal(filepath.Join(active, "zsh", "_rg")))
	})

	It("prunes a host link when its completion is no longer wanted", func() {
		active := filepath.Join(GinkgoT().TempDir(), "active", "completions")
		full := filepath.Join(active, "bash", "rg")
		Expect(os.MkdirAll(filepath.Dir(full), 0o750)).To(Succeed())
		Expect(os.WriteFile(full, []byte("comp"), 0o644)).To(Succeed())
		hostDirs := map[string]string{"bash": GinkgoT().TempDir(), "zsh": GinkgoT().TempDir(), "fish": GinkgoT().TempDir()}
		_, err := completion.Reconcile(hostDirs, active, []completion.Want{{Shell: "bash", HostFile: "rg"}})
		Expect(err).NotTo(HaveOccurred())
		res, err := completion.Reconcile(hostDirs, active, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res["bash"].Pruned).To(Equal([]string{"rg"}))
	})
})

var _ = Describe("PruneAll", func() {
	It("removes ours-links across all shells and leaves foreign files", func() {
		active := filepath.Join(GinkgoT().TempDir(), "active", "completions")
		full := filepath.Join(active, "fish", "rg.fish")
		Expect(os.MkdirAll(filepath.Dir(full), 0o750)).To(Succeed())
		Expect(os.WriteFile(full, []byte("comp"), 0o644)).To(Succeed())
		hostDirs := map[string]string{"bash": GinkgoT().TempDir(), "zsh": GinkgoT().TempDir(), "fish": GinkgoT().TempDir()}
		_, err := completion.Reconcile(hostDirs, active, []completion.Want{{Shell: "fish", HostFile: "rg.fish"}})
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(filepath.Join(hostDirs["fish"], "foreign.fish"), []byte("x"), 0o644)).To(Succeed())
		pruned, err := completion.PruneAll(hostDirs, active)
		Expect(err).NotTo(HaveOccurred())
		Expect(pruned["fish"]).To(Equal([]string{"rg.fish"}))
		_, statErr := os.Lstat(filepath.Join(hostDirs["fish"], "foreign.fish"))
		Expect(statErr).NotTo(HaveOccurred())
	})
})

func TestCompletion(t *testing.T) { RegisterFailHandler(Fail); RunSpecs(t, "completion") }
