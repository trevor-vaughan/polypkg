package mime_test

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/mime"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("ExposedMimeEntries", func() {
	It("selects mime entries and parses the filename, dropping malformed", func() {
		entries := []schema.OwnershipEntry{
			{Path: "mime/tool.xml", Action: "mime"},
			{Path: "bin/rg", Action: "path"},         // not mime
			{Path: "mime", Action: "mime"},           // malformed (no file)
			{Path: "mime/sub/x.xml", Action: "mime"}, // malformed (extra segment)
		}
		Expect(mime.ExposedMimeEntries(entries)).To(Equal([]string{"tool.xml"}))
	})
})

var _ = Describe("Reconcile / PruneAll", func() {
	setup := func() (pkgDir, activeDir string) {
		activeDir = filepath.Join(GinkgoT().TempDir(), "active", "mime")
		Expect(os.MkdirAll(activeDir, 0o750)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(activeDir, "tool.xml"), []byte("x"), 0o644)).To(Succeed())
		return GinkgoT().TempDir(), activeDir
	}
	entries := []schema.OwnershipEntry{{Path: "mime/tool.xml", Action: "mime"}}

	It("links the host mime packages dir to the active area", func() {
		pkgDir, activeDir := setup()
		res, err := mime.Reconcile(pkgDir, activeDir, entries)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Linked).To(Equal([]string{"tool.xml"}))
		tgt, _ := os.Readlink(filepath.Join(pkgDir, "tool.xml"))
		Expect(tgt).To(Equal(filepath.Join(activeDir, "tool.xml")))
	})

	It("prunes ours-links and leaves foreign files", func() {
		pkgDir, activeDir := setup()
		_, err := mime.Reconcile(pkgDir, activeDir, entries)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(filepath.Join(pkgDir, "foreign.xml"), []byte("mine"), 0o644)).To(Succeed())
		pruned, err := mime.PruneAll(pkgDir, activeDir)
		Expect(err).NotTo(HaveOccurred())
		Expect(pruned).To(Equal([]string{"tool.xml"}))
		_, statErr := os.Lstat(filepath.Join(pkgDir, "foreign.xml"))
		Expect(statErr).NotTo(HaveOccurred())
	})
})

func TestMime(t *testing.T) { RegisterFailHandler(Fail); RunSpecs(t, "mime") }
