package alternatives_test

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/alternatives"
)

var _ = Describe("Selection store", func() {
	It("SelectionsPath joins the state root with the store filename", func() {
		Expect(alternatives.SelectionsPath("/x/state")).
			To(Equal(filepath.Join("/x/state", alternatives.SelectionsFile)))
	})

	It("LoadSelections returns an empty non-nil map when the file is absent", func() {
		sel, err := alternatives.LoadSelections(filepath.Join(GinkgoT().TempDir(), "nope.json"))
		Expect(err).NotTo(HaveOccurred())
		Expect(sel).NotTo(BeNil())
		Expect(sel).To(BeEmpty())
	})

	It("round-trips selections through Save and Load", func() {
		path := filepath.Join(GinkgoT().TempDir(), "sel.json")
		Expect(alternatives.SaveSelections(path, alternatives.Selections{"editor": "vim", "pager": "less"})).To(Succeed())
		sel, err := alternatives.LoadSelections(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(sel).To(Equal(alternatives.Selections{"editor": "vim", "pager": "less"}))
	})

	It("writes the store at mode 0600 and leaves no temp file", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "sel.json")
		Expect(alternatives.SaveSelections(path, alternatives.Selections{"editor": "vim"})).To(Succeed())
		info, err := os.Stat(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))
		_, terr := os.Stat(path + ".tmp")
		Expect(os.IsNotExist(terr)).To(BeTrue())
	})

	It("creates the parent state directory if absent", func() {
		path := filepath.Join(GinkgoT().TempDir(), "state", "sel.json")
		Expect(alternatives.SaveSelections(path, alternatives.Selections{})).To(Succeed())
		_, err := os.Stat(path)
		Expect(err).NotTo(HaveOccurred())
	})

	It("errors on a malformed store rather than silently resetting it", func() {
		path := filepath.Join(GinkgoT().TempDir(), "sel.json")
		Expect(os.WriteFile(path, []byte("{not json"), 0o600)).To(Succeed())
		_, err := alternatives.LoadSelections(path)
		Expect(err).To(HaveOccurred())
	})
})
