package action

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Perms", func() {
	It("sets file mode", func() {
		dir := GinkgoT().TempDir()
		scope := Scope{
			ActiveRoot:  filepath.Join(dir, "active"),
			PackageName: "hello",
		}
		target := filepath.Join(scope.ActiveRoot, "hello", "f")
		Expect(os.MkdirAll(filepath.Dir(target), 0o755)).To(Succeed())
		Expect(os.WriteFile(target, []byte("x"), 0o600)).To(Succeed())

		inv := Invocation{
			Action: "perms",
			Params: map[string]any{
				"path": target,
				"mode": "0o755",
			},
		}
		_, err := Perms(inv, scope)
		Expect(err).NotTo(HaveOccurred())

		info, err := os.Stat(target)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o755)))
	})

	It("captures mode in the expected fingerprint", func() {
		dir := GinkgoT().TempDir()
		active := filepath.Join(dir, "active")
		scope := Scope{ActiveRoot: active, PackageName: "hello"}
		_, err := Dir(Invocation{Action: "dir", PackageName: "hello", Params: map[string]any{
			"path": filepath.Join(active, "hello/bin"), "mode": "0o755"}}, scope)
		Expect(err).NotTo(HaveOccurred())

		res, err := Perms(Invocation{Action: "perms", PackageName: "hello", Params: map[string]any{
			"path": filepath.Join(active, "hello/bin"), "mode": "0o700"}}, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Expected.Mode).To(Equal("0700"))
		Expect(res.Stat.Inode).NotTo(BeZero())
	})

	DescribeTable("rejects unsupported ownership keys (M1 supports mode only)",
		func(key string) {
			dir := GinkgoT().TempDir()
			scope := Scope{ActiveRoot: filepath.Join(dir, "active"), PackageName: "hello"}
			target := filepath.Join(scope.ActiveRoot, "hello", "f")
			Expect(os.MkdirAll(filepath.Dir(target), 0o755)).To(Succeed())
			Expect(os.WriteFile(target, []byte("x"), 0o600)).To(Succeed())

			inv := Invocation{Action: "perms", Params: map[string]any{
				"path": target,
				key:    "root",
			}}
			res, err := Perms(inv, scope)
			// M1 perms supports mode only. An unsupported ownership param must
			// be a loud error, never a silent success that misleads the author
			// into believing ownership was applied.
			Expect(err).To(HaveOccurred(), "perms must reject %q in M1", key)
			Expect(err.Error()).To(ContainSubstring(key))
			Expect(res.Outcome).To(Equal("error"))
		},
		Entry("owner", "owner"),
		Entry("group", "group"),
	)
})
