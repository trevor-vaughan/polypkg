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

	DescribeTable("rejects ownership keys, since perms sets the mode only",
		func(key, want string) {
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
			// An unsupported ownership param must be a loud error, never a
			// silent success that misleads the author into believing
			// ownership was applied.
			Expect(err).To(HaveOccurred(), "perms must reject %q", key)
			Expect(err.Error()).To(Equal(want))
			Expect(res.Outcome).To(Equal("error"))
		},
		Entry("owner", "owner", "perms: setting an owner is not supported; only mode can be set"),
		Entry("group", "group", "perms: setting a group is not supported; only mode can be set"),
	)

	DescribeTable("refuses a mode outside 0755 and leaves the file untouched",
		func(mode, bits string) {
			dir := GinkgoT().TempDir()
			scope := Scope{ActiveRoot: filepath.Join(dir, "active"), PackageName: "hello"}
			target := filepath.Join(scope.ActiveRoot, "hello", "f")
			Expect(os.MkdirAll(filepath.Dir(target), 0o755)).To(Succeed())
			Expect(os.WriteFile(target, []byte("x"), 0o600)).To(Succeed())
			Expect(os.Chmod(target, 0o600)).To(Succeed())

			res, err := Perms(Invocation{Action: "perms", Params: map[string]any{
				"path": target,
				"mode": mode,
			}}, scope)
			Expect(err).To(HaveOccurred(), "perms must refuse mode %s", mode)
			Expect(err.Error()).To(ContainSubstring(target), "the error names the path")
			Expect(err.Error()).To(ContainSubstring(`"`+mode+`"`), "the error names the mode as written")
			Expect(err.Error()).To(ContainSubstring("sets " + bits + ";"))
			Expect(res.Outcome).To(Equal("error"))

			info, statErr := os.Stat(target)
			Expect(statErr).NotTo(HaveOccurred())
			Expect(info.Mode()).To(Equal(os.FileMode(0o600)), "a refused mode must not chmod the file")
		},
		Entry("world-writable 0o777", "0o777", "group-write, other-write"),
		Entry("world-writable 0666", "0666", "group-write, other-write"),
		Entry("other-write 0o646", "0o646", "other-write"),
		Entry("group-write 0o664", "0o664", "group-write"),
		Entry("setuid 0o4755", "0o4755", "setuid"),
		Entry("setgid 0o2755", "0o2755", "setgid"),
		Entry("sticky 0o1644", "0o1644", "sticky"),
		Entry("a value above 0o7777 that os.FileMode reads as ModeSetuid", "0o40000755", "bits outside 0o7777"),
	)

	It("refuses an unsafe mode before creating the scope", func() {
		dir := GinkgoT().TempDir()
		scope := Scope{ActiveRoot: filepath.Join(dir, "active"), PackageName: "hello"}
		target := filepath.Join(scope.ActiveRoot, "hello", "f")

		res, err := Perms(Invocation{Action: "perms", Params: map[string]any{
			"path": target,
			"mode": "0o777",
		}}, scope)
		Expect(err).To(MatchError(ContainSubstring(`refusing mode "0o777"`)))
		Expect(res.Outcome).To(Equal("error"))

		_, statErr := os.Stat(scope.ActiveRoot)
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "a refused mode must not create the scope")
	})

	DescribeTable("applies a mode within 0755",
		func(mode string, want os.FileMode) {
			dir := GinkgoT().TempDir()
			scope := Scope{ActiveRoot: filepath.Join(dir, "active"), PackageName: "hello"}
			target := filepath.Join(scope.ActiveRoot, "hello", "f")
			Expect(os.MkdirAll(filepath.Dir(target), 0o755)).To(Succeed())
			Expect(os.WriteFile(target, []byte("x"), 0o600)).To(Succeed())

			res, err := Perms(Invocation{Action: "perms", Params: map[string]any{
				"path": target,
				"mode": mode,
			}}, scope)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Outcome).To(Equal("ok"))

			info, err := os.Stat(target)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode()).To(Equal(want))
		},
		Entry("0o755", "0o755", os.FileMode(0o755)),
		Entry("0o644", "0o644", os.FileMode(0o644)),
		Entry("0o640", "0o640", os.FileMode(0o640)),
		Entry("0o500", "0o500", os.FileMode(0o500)),
		Entry("0444 without the 0o prefix", "0444", os.FileMode(0o444)),
	)
})
