package desktop_test

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/desktop"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("ExposedDesktopEntries", func() {
	It("selects desktop entries and parses the filename, dropping malformed", func() {
		entries := []schema.OwnershipEntry{
			{Path: "applications/org.foo.Bar.desktop", Action: "desktop"},
			{Path: "bin/rg", Action: "path"},                        // not desktop
			{Path: "applications", Action: "desktop"},               // malformed (no file)
			{Path: "applications/sub/x.desktop", Action: "desktop"}, // malformed (extra segment)
		}
		Expect(desktop.ExposedDesktopEntries(entries)).To(Equal([]string{"org.foo.Bar.desktop"}))
	})
})

var _ = Describe("Reconcile / PruneAll", func() {
	setup := func() (appsDir, activeDir string) {
		activeDir = filepath.Join(GinkgoT().TempDir(), "active", "applications")
		Expect(os.MkdirAll(activeDir, 0o750)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(activeDir, "org.foo.Bar.desktop"), []byte("x"), 0o644)).To(Succeed())
		return GinkgoT().TempDir(), activeDir
	}
	entries := []schema.OwnershipEntry{{Path: "applications/org.foo.Bar.desktop", Action: "desktop"}}

	It("links the host applications dir to the active area", func() {
		appsDir, activeDir := setup()
		res, err := desktop.Reconcile(appsDir, activeDir, entries)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Linked).To(Equal([]string{"org.foo.Bar.desktop"}))
		tgt, _ := os.Readlink(filepath.Join(appsDir, "org.foo.Bar.desktop"))
		Expect(tgt).To(Equal(filepath.Join(activeDir, "org.foo.Bar.desktop")))
	})

	It("prunes ours-links and leaves foreign files", func() {
		appsDir, activeDir := setup()
		_, err := desktop.Reconcile(appsDir, activeDir, entries)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(filepath.Join(appsDir, "foreign.desktop"), []byte("mine"), 0o644)).To(Succeed())
		pruned, err := desktop.PruneAll(appsDir, activeDir)
		Expect(err).NotTo(HaveOccurred())
		Expect(pruned).To(Equal([]string{"org.foo.Bar.desktop"}))
		_, statErr := os.Lstat(filepath.Join(appsDir, "foreign.desktop"))
		Expect(statErr).NotTo(HaveOccurred())
	})
})

func TestDesktop(t *testing.T) { RegisterFailHandler(Fail); RunSpecs(t, "desktop") }
