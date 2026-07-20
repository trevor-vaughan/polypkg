package action

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("openSharedSubtree", func() {
	It("confines a write to <ActiveRoot>/rel and creates a multi-segment rel", func() {
		dir := GinkgoT().TempDir()
		scope := Scope{ActiveRoot: filepath.Join(dir, "active")}
		root, err := scope.openSharedSubtree(filepath.Join("a", "b"))
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = root.Close() }()
		Expect(root.Symlink("/target", "x")).To(Succeed())
		tgt, err := os.Readlink(filepath.Join(scope.ActiveRoot, "a", "b", "x"))
		Expect(err).NotTo(HaveOccurred())
		Expect(tgt).To(Equal("/target"))
	})
})
