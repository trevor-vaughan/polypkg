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

	DescribeTable("refuses a mode outside 0755 before touching the filesystem",
		func(mode, bits string) {
			dir := GinkgoT().TempDir()
			scope := Scope{ActiveRoot: filepath.Join(dir, "active"), PackageName: "hello"}
			target := filepath.Join(scope.ActiveRoot, "hello", "data")

			res, err := Dir(Invocation{Action: "dir", Params: map[string]any{
				"path": target,
				"mode": mode,
			}}, scope)
			Expect(err).To(HaveOccurred(), "dir must refuse mode %s", mode)
			Expect(err.Error()).To(ContainSubstring(target), "the error names the path")
			Expect(err.Error()).To(ContainSubstring(`"`+mode+`"`), "the error names the mode as written")
			Expect(err.Error()).To(ContainSubstring("sets " + bits + ";"))
			Expect(res.Outcome).To(Equal("error"))

			_, statErr := os.Stat(scope.ActiveRoot)
			Expect(os.IsNotExist(statErr)).To(BeTrue(), "a refused mode must not create anything")
		},
		Entry("world-writable 0o777", "0o777", "group-write, other-write"),
		Entry("other-write 0o757", "0o757", "other-write"),
		Entry("other-write without the 0o prefix", "0757", "other-write"),
		Entry("group-write 0o775", "0o775", "group-write"),
		Entry("setuid 0o4755", "0o4755", "setuid"),
		Entry("setgid 0o2755", "0o2755", "setgid"),
		Entry("sticky 0o1755", "0o1755", "sticky"),
		Entry("every special bit 0o7777", "0o7777", "setuid, setgid, sticky, group-write, other-write"),
		Entry("a value above 0o7777 that os.FileMode reads as ModeSetuid", "0o40000755", "bits outside 0o7777"),
	)

	DescribeTable("applies a mode within 0755",
		func(mode string, want os.FileMode) {
			dir := GinkgoT().TempDir()
			scope := Scope{ActiveRoot: filepath.Join(dir, "active"), PackageName: "hello"}
			target := filepath.Join(scope.ActiveRoot, "hello", "data")

			res, err := Dir(Invocation{Action: "dir", Params: map[string]any{
				"path": target,
				"mode": mode,
			}}, scope)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Outcome).To(Equal("ok"))

			info, err := os.Stat(target)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(want))
			Expect(info.Mode() & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky)).To(BeZero())
		},
		Entry("0o755", "0o755", os.FileMode(0o755)),
		Entry("0o750", "0o750", os.FileMode(0o750)),
		Entry("0o711", "0o711", os.FileMode(0o711)),
		Entry("0o700", "0o700", os.FileMode(0o700)),
		Entry("0o555", "0o555", os.FileMode(0o555)),
		Entry("0755 without the 0o prefix", "0755", os.FileMode(0o755)),
	)
})
