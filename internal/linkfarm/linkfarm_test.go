package linkfarm_test

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/linkfarm"
)

// fixture returns an empty target dir and an owned dir holding the named files.
func fixture(owned ...string) (dir, ownedDir string) {
	dir = GinkgoT().TempDir()
	ownedDir = filepath.Join(GinkgoT().TempDir(), "owned")
	Expect(os.MkdirAll(ownedDir, 0o750)).To(Succeed())
	for _, n := range owned {
		Expect(os.WriteFile(filepath.Join(ownedDir, n), []byte("x"), 0o644)).To(Succeed())
	}
	return dir, ownedDir
}

func want(ownedDir string, names ...string) map[string]string {
	m := map[string]string{}
	for _, n := range names {
		m[n] = filepath.Join(ownedDir, n)
	}
	return m
}

var _ = Describe("Reconcile", func() {
	It("links a new entry to its owned target", func() {
		dir, owned := fixture("rg")
		res, err := linkfarm.Reconcile(dir, owned, want(owned, "rg"))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Linked).To(Equal([]string{"rg"}))
		tgt, _ := os.Readlink(filepath.Join(dir, "rg"))
		Expect(tgt).To(Equal(filepath.Join(owned, "rg")))
	})

	It("is idempotent on an already-correct ours-link", func() {
		dir, owned := fixture("rg")
		_, err := linkfarm.Reconcile(dir, owned, want(owned, "rg"))
		Expect(err).NotTo(HaveOccurred())
		res, err := linkfarm.Reconcile(dir, owned, want(owned, "rg"))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Linked).To(BeEmpty())
		Expect(res.Pruned).To(BeEmpty())
	})

	It("repoints a stale ours-link (target still inside ownedDir)", func() {
		dir, owned := fixture("rg")
		Expect(os.Symlink(filepath.Join(owned, "stale"), filepath.Join(dir, "rg"))).To(Succeed())
		res, err := linkfarm.Reconcile(dir, owned, want(owned, "rg"))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Linked).To(Equal([]string{"rg"}))
		tgt, _ := os.Readlink(filepath.Join(dir, "rg"))
		Expect(tgt).To(Equal(filepath.Join(owned, "rg")))
	})

	It("prunes an ours-link no longer wanted", func() {
		dir, owned := fixture("rg")
		_, err := linkfarm.Reconcile(dir, owned, want(owned, "rg"))
		Expect(err).NotTo(HaveOccurred())
		res, err := linkfarm.Reconcile(dir, owned, want(owned))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Pruned).To(Equal([]string{"rg"}))
		_, statErr := os.Lstat(filepath.Join(dir, "rg"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
	})

	It("skips a foreign plain file and never removes it", func() {
		dir, owned := fixture("rg")
		Expect(os.WriteFile(filepath.Join(dir, "rg"), []byte("mine"), 0o644)).To(Succeed())
		res, err := linkfarm.Reconcile(dir, owned, want(owned, "rg"))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Linked).To(BeEmpty())
		Expect(res.Skipped).To(HaveLen(1))
		Expect(res.Skipped[0].Name).To(Equal("rg"))
		b, _ := os.ReadFile(filepath.Join(dir, "rg"))
		Expect(string(b)).To(Equal("mine"))
	})

	It("skips a foreign symlink pointing outside ownedDir", func() {
		dir, owned := fixture("rg")
		Expect(os.Symlink("/somewhere/else/rg", filepath.Join(dir, "rg"))).To(Succeed())
		res, err := linkfarm.Reconcile(dir, owned, want(owned, "rg"))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Skipped).To(HaveLen(1))
		Expect(res.Skipped[0].Existing).To(Equal("/somewhere/else/rg"))
	})

	It("rejects a non-component link name", func() {
		dir, owned := fixture()
		_, err := linkfarm.Reconcile(dir, owned, map[string]string{"a/b": filepath.Join(owned, "a", "b")})
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("PruneAll", func() {
	It("removes only ours-links and is a no-op on a missing dir", func() {
		dir, owned := fixture("rg")
		_, err := linkfarm.Reconcile(dir, owned, want(owned, "rg"))
		Expect(err).NotTo(HaveOccurred())
		Expect(os.Symlink("/foreign", filepath.Join(dir, "keep"))).To(Succeed())
		pruned, err := linkfarm.PruneAll(dir, owned)
		Expect(err).NotTo(HaveOccurred())
		Expect(pruned).To(Equal([]string{"rg"}))
		_, statErr := os.Lstat(filepath.Join(dir, "keep"))
		Expect(statErr).NotTo(HaveOccurred())

		missing := filepath.Join(GinkgoT().TempDir(), "nope")
		p2, err := linkfarm.PruneAll(missing, owned)
		Expect(err).NotTo(HaveOccurred())
		Expect(p2).To(BeEmpty())
	})
})

func TestLinkfarm(t *testing.T) { RegisterFailHandler(Fail); RunSpecs(t, "linkfarm") }
