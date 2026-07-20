package substrate

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OwnStore directory mode", func() {
	It("creates generation directories at 0o700 by default", func() {
		root := filepath.Join(GinkgoT().TempDir(), "sub")
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.BeginTransaction("tx")).To(Succeed())
		fi, err := os.Stat(filepath.Join(root, "generations", "1"))
		Expect(err).NotTo(HaveOccurred())
		Expect(fi.Mode().Perm()).To(Equal(os.FileMode(0o700)))
	})

	It("creates generation and active directories at the WithDirMode mode", func() {
		root := filepath.Join(GinkgoT().TempDir(), "sub")
		s, err := NewOwnStore(root, WithDirMode(0o755))
		Expect(err).NotTo(HaveOccurred())
		Expect(s.BeginTransaction("tx")).To(Succeed())
		for _, p := range []string{
			filepath.Join(root, "generations", "1"),
			filepath.Join(root, "generations", "1", "active"),
		} {
			fi, err := os.Stat(p)
			Expect(err).NotTo(HaveOccurred(), p)
			Expect(fi.Mode().Perm()).To(Equal(os.FileMode(0o755)), p)
		}
	})
})
