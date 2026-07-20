package action

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Scope directory mode", func() {
	It("creates shared-subtree dirs at 0o700 by default", func() {
		active := filepath.Join(GinkgoT().TempDir(), "active")
		s := Scope{ActiveRoot: active}
		root, err := s.openSharedSubtree("bin")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = root.Close() }()
		fi, err := os.Stat(filepath.Join(active, "bin"))
		Expect(err).NotTo(HaveOccurred())
		Expect(fi.Mode().Perm()).To(Equal(os.FileMode(0o700)))
	})

	It("creates the active root and shared subtree at DirMode", func() {
		active := filepath.Join(GinkgoT().TempDir(), "active")
		s := Scope{ActiveRoot: active, DirMode: 0o755}
		root, err := s.openSharedSubtree("bin")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = root.Close() }()
		for _, p := range []string{active, filepath.Join(active, "bin")} {
			fi, err := os.Stat(p)
			Expect(err).NotTo(HaveOccurred(), p)
			Expect(fi.Mode().Perm()).To(Equal(os.FileMode(0o755)), p)
		}
	})

	It("creates the package scope dir at DirMode (openScope)", func() {
		active := filepath.Join(GinkgoT().TempDir(), "active")
		s := Scope{ActiveRoot: active, PackageName: "hello", DirMode: 0o755}
		root, rel, err := s.openScope(filepath.Join(active, "hello", "bin", "hi"))
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = root.Close() }()
		Expect(rel).To(Equal(filepath.Join("bin", "hi")))
		// openScope creates the active root too; assert both levels carry DirMode.
		for _, p := range []string{active, filepath.Join(active, "hello")} {
			fi, err := os.Stat(p)
			Expect(err).NotTo(HaveOccurred(), p)
			Expect(fi.Mode().Perm()).To(Equal(os.FileMode(0o755)), p)
		}
	})
})
