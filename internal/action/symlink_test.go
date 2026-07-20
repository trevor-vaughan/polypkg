package action

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Symlink", func() {
	It("creates the link", func() {
		dir := GinkgoT().TempDir()
		scope := Scope{
			ActiveRoot:  filepath.Join(dir, "active"),
			PackageName: "hello",
		}
		src := "/some/external/target"
		dest := filepath.Join(scope.ActiveRoot, "hello", "link")

		inv := Invocation{
			Action:      "symlink",
			PackageName: "hello",
			Params: map[string]any{
				"src":  src,
				"dest": dest,
			},
		}
		_, err := Symlink(inv, scope)
		Expect(err).NotTo(HaveOccurred())

		got, err := os.Readlink(dest)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(src))
	})

	It("captures the symlink target in the expected fingerprint", func() {
		dir := GinkgoT().TempDir()
		active := filepath.Join(dir, "active")
		scope := Scope{ActiveRoot: active, PackageName: "hello"}
		inv := Invocation{Action: "symlink", PackageName: "hello", Params: map[string]any{
			"src":  "bin/hi",
			"dest": filepath.Join(active, "hello/bin/hi-link"),
		}}
		res, err := Symlink(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Expected.FileType).To(Equal("symlink"))
		Expect(res.Expected.Target).To(Equal("bin/hi"))
		Expect(res.Stat.Inode).NotTo(BeZero())
	})

	It("rejects a dest outside scope", func() {
		dir := GinkgoT().TempDir()
		scope := Scope{
			ActiveRoot:  filepath.Join(dir, "active"),
			PackageName: "hello",
		}
		inv := Invocation{
			Action:      "symlink",
			PackageName: "hello",
			Params: map[string]any{
				"src":  "/x",
				"dest": "/etc/y",
			},
		}
		_, err := Symlink(inv, scope)
		Expect(err).To(HaveOccurred())
	})
})
