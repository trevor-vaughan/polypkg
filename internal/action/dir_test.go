package action

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Dir", func() {
	It("captures mode in the expected fingerprint", func() {
		dir := GinkgoT().TempDir()
		active := filepath.Join(dir, "active")
		scope := Scope{ActiveRoot: active, PackageName: "hello"}
		inv := Invocation{Action: "dir", PackageName: "hello", Params: map[string]any{
			"path": filepath.Join(active, "hello/bin"),
			"mode": "0o750",
		}}
		res, err := Dir(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Expected.FileType).To(Equal("dir"))
		Expect(res.Expected.Mode).To(Equal("0750"))
		Expect(res.Stat.Inode).NotTo(BeZero())
	})

	It("creates the target directory", func() {
		dir := GinkgoT().TempDir()
		scope := Scope{
			ActiveRoot:  filepath.Join(dir, "active"),
			PackageName: "hello",
		}
		target := filepath.Join(scope.ActiveRoot, "hello", "data")

		inv := Invocation{
			Action: "dir",
			Params: map[string]any{
				"path": target,
				"mode": "0o755",
			},
		}
		_, err := Dir(inv, scope)
		Expect(err).NotTo(HaveOccurred())

		info, err := os.Stat(target)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.IsDir()).To(BeTrue())
	})
})
