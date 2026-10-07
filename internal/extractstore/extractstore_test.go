package extractstore_test

import (
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/extractstore"
)

var _ = Describe("naming", func() {
	It("keys a dir by name, version, and hash prefix", func() {
		Expect(extractstore.DirName("greet", "1.0.0", "blake3:b4ff3a151039b63dbfb85c7d4f8572587b16c6af3e5ef7d1ae69059c57899482")).
			To(Equal("greet-1.0.0+b4ff3a151039b63d"))
	})
	It("tolerates a short hash", func() {
		Expect(extractstore.DirName("x", "1", "blake3:abcd")).To(Equal("x-1+abcd"))
	})
	It("legacy name is the pre-content-addressed layout", func() {
		Expect(extractstore.LegacyDirName("greet", "1.0.0")).To(Equal("greet-1.0.0"))
	})
	It("Dir joins Root and DirName", func() {
		Expect(extractstore.Dir("/state", "greet", "1.0.0", "blake3:aa11223344556677889900")).
			To(Equal(filepath.Join("/state", "pkg-extract", "greet-1.0.0+aa11223344556677")))
	})
})

var _ = Describe("Sweep", func() {
	var state string

	// age backdates dir so a minAge of time.Hour sees it as old.
	age := func(dir string) {
		GinkgoHelper()
		old := time.Now().Add(-2 * time.Hour)
		Expect(os.Chtimes(dir, old, old)).To(Succeed())
	}

	BeforeEach(func() {
		state = GinkgoT().TempDir()
		root := filepath.Join(state, "pkg-extract")
		// legacy layout dir (keep-1.0.0) is referenced; .extract-12345 is a crashed temp
		for _, name := range []string{"keep-1.0.0+aabbccddeeff0011", "keep-1.0.0", "gone-2.0.0+1122334455667788", ".extract-12345"} {
			dir := filepath.Join(root, name)
			Expect(os.MkdirAll(dir, 0o700)).To(Succeed())
			age(dir)
		}
	})

	It("removes everything not in keep, including crashed temp dirs", func() {
		keep := map[string]bool{
			"keep-1.0.0+aabbccddeeff0011": true,
			"keep-1.0.0":                  true,
		}
		removed, err := extractstore.Sweep(state, keep, time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal([]string{".extract-12345", "gone-2.0.0+1122334455667788"}), "basenames, in directory (sorted) order")
		Expect(filepath.Join(state, "pkg-extract", "keep-1.0.0+aabbccddeeff0011")).To(BeADirectory())
		Expect(filepath.Join(state, "pkg-extract", "keep-1.0.0")).To(BeADirectory())
		Expect(filepath.Join(state, "pkg-extract", "gone-2.0.0+1122334455667788")).NotTo(BeADirectory())
		Expect(filepath.Join(state, "pkg-extract", ".extract-12345")).NotTo(BeADirectory())
	})

	It("keeps young entries even when unreferenced", func() {
		fresh := filepath.Join(state, "pkg-extract", "young-3.0.0+99aabbccddeeff00")
		Expect(os.MkdirAll(fresh, 0o700)).To(Succeed())
		keep := map[string]bool{
			"keep-1.0.0+aabbccddeeff0011": true,
			"keep-1.0.0":                  true,
			"gone-2.0.0+1122334455667788": true,
			".extract-12345":              true,
		}
		removed, err := extractstore.Sweep(state, keep, time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(BeEmpty())
		Expect(removed).NotTo(BeNil(), "an empty sweep marshals as [], not null")
		Expect(fresh).To(BeADirectory())
	})

	It("minAge zero removes regardless of age", func() {
		fresh := filepath.Join(state, "pkg-extract", "young-3.0.0+99aabbccddeeff00")
		Expect(os.MkdirAll(fresh, 0o700)).To(Succeed())
		removed, err := extractstore.Sweep(state, map[string]bool{}, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(HaveLen(5))
		Expect(removed).To(ContainElement("young-3.0.0+99aabbccddeeff00"))
		Expect(fresh).NotTo(BeADirectory())
	})

	It("treats a missing root as empty", func() {
		removed, err := extractstore.Sweep(GinkgoT().TempDir(), map[string]bool{}, time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(BeEmpty())
		Expect(removed).NotTo(BeNil())
	})
})
