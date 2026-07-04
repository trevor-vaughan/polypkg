package action

import (
	"encoding/hex"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"lukechampine.com/blake3"
)

func blake3Hex(b []byte) string {
	h := blake3.New(32, nil)
	_, _ = h.Write(b)
	return "blake3:" + hex.EncodeToString(h.Sum(nil))
}

var _ = Describe("Install", func() {
	It("places a symlink for policy=symlink", func() {
		dir := GinkgoT().TempDir()
		srcDir := filepath.Join(dir, "store/abc-hello-1.0/content")
		Expect(os.MkdirAll(srcDir, 0o755)).To(Succeed())
		srcFile := filepath.Join(srcDir, "hi")
		Expect(os.WriteFile(srcFile, []byte("data"), 0o644)).To(Succeed())

		scope := Scope{
			ActiveRoot:  filepath.Join(dir, "active"),
			PackageName: "hello",
			PackageRoot: srcDir,
		}
		dest := filepath.Join(scope.ActiveRoot, "hello", "bin", "hi")

		inv := Invocation{
			Action:      "install",
			PackageName: "hello",
			Phase:       PhasePostPlace,
			Params: map[string]any{
				"src":    srcFile,
				"dest":   dest,
				"policy": "symlink",
			},
		}
		result, err := Install(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Outcome).To(Equal("ok"))

		info, err := os.Lstat(dest)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode() & os.ModeSymlink).NotTo(BeZero())
	})

	It("copies a regular file for policy=copy", func() {
		dir := GinkgoT().TempDir()
		srcDir := filepath.Join(dir, "store/abc-hello-1.0/content")
		Expect(os.MkdirAll(srcDir, 0o755)).To(Succeed())
		srcFile := filepath.Join(srcDir, "hi")
		Expect(os.WriteFile(srcFile, []byte("data"), 0o644)).To(Succeed())

		scope := Scope{
			ActiveRoot:  filepath.Join(dir, "active"),
			PackageName: "hello",
			PackageRoot: srcDir,
		}
		dest := filepath.Join(scope.ActiveRoot, "hello", "bin", "hi")

		inv := Invocation{
			Action:      "install",
			PackageName: "hello",
			Phase:       PhasePostPlace,
			Params: map[string]any{
				"src":    srcFile,
				"dest":   dest,
				"policy": "copy",
			},
		}
		_, err := Install(inv, scope)
		Expect(err).NotTo(HaveOccurred())

		info, err := os.Lstat(dest)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().IsRegular()).To(BeTrue())

		data, err := os.ReadFile(dest)
		Expect(err).NotTo(HaveOccurred())
		Expect(data).To(Equal([]byte("data")))
	})

	It("creates a hardlink for policy=hardlink", func() {
		dir := GinkgoT().TempDir()
		pkgRoot := filepath.Join(dir, "pkg")
		Expect(os.MkdirAll(pkgRoot, 0o755)).To(Succeed())
		srcFile := filepath.Join(pkgRoot, "hi")
		Expect(os.WriteFile(srcFile, []byte("data"), 0o644)).To(Succeed())

		scope := Scope{
			ActiveRoot:  filepath.Join(dir, "active"),
			PackageName: "hello",
			PackageRoot: pkgRoot,
		}
		dest := filepath.Join(scope.ActiveRoot, "hello", "bin", "hi")
		inv := Invocation{
			Action: "install", PackageName: "hello", Phase: PhasePostPlace,
			Params: map[string]any{"src": srcFile, "dest": dest, "policy": "hardlink"},
		}
		_, err := Install(inv, scope)
		Expect(err).NotTo(HaveOccurred())

		si, err := os.Stat(srcFile)
		Expect(err).NotTo(HaveOccurred())
		di, err := os.Stat(dest)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.SameFile(si, di)).To(BeTrue(), "dest must be a hardlink to the source file")
	})

	It("captures expected fingerprint for policy=hardlink", func() {
		dir := GinkgoT().TempDir()
		pkgRoot := filepath.Join(dir, "pkg")
		Expect(os.MkdirAll(pkgRoot, 0o755)).To(Succeed())
		content := []byte("data")
		srcFile := filepath.Join(pkgRoot, "hi")
		Expect(os.WriteFile(srcFile, content, 0o644)).To(Succeed())

		scope := Scope{ActiveRoot: filepath.Join(dir, "active"), PackageName: "hello", PackageRoot: pkgRoot}
		dest := filepath.Join(scope.ActiveRoot, "hello", "bin", "hi")
		res, err := Install(Invocation{
			Action: "install", PackageName: "hello", Phase: PhasePostPlace,
			Params: map[string]any{"src": srcFile, "dest": dest, "policy": "hardlink"},
		}, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Expected.FileType).To(Equal("regular"))
		Expect(res.Expected.ContentHash).To(Equal(blake3Hex(content)))
		Expect(res.Stat.Inode).NotTo(BeZero())
	})

	DescribeTable("rejects a src outside the package",
		func(policy string) {
			dir := GinkgoT().TempDir()
			pkgRoot := filepath.Join(dir, "pkg")
			Expect(os.MkdirAll(pkgRoot, 0o755)).To(Succeed())
			scope := Scope{
				ActiveRoot:  filepath.Join(dir, "active"),
				PackageName: "hello",
				PackageRoot: pkgRoot,
			}
			// A file outside the package's own extracted directory.
			secret := filepath.Join(dir, "secret")
			Expect(os.WriteFile(secret, []byte("top secret"), 0o644)).To(Succeed())
			dest := filepath.Join(scope.ActiveRoot, "hello", "leak")

			inv := Invocation{
				Action: "install", PackageName: "hello", Phase: PhasePostPlace,
				Params: map[string]any{"src": secret, "dest": dest, "policy": policy},
			}
			_, err := Install(inv, scope)
			Expect(err).To(HaveOccurred(), "install policy=%s must refuse a src outside the package", policy)
			Expect(err.Error()).To(ContainSubstring("src"))
			_, statErr := os.Lstat(dest)
			Expect(statErr).To(HaveOccurred(), "nothing may be placed when src is rejected (policy=%s)", policy)
		},
		Entry("policy=copy", "copy"),
		Entry("policy=symlink", "symlink"),
		Entry("policy=hardlink", "hardlink"),
	)

	It("captures expected fingerprint for policy=symlink", func() {
		dir := GinkgoT().TempDir()
		pkgRoot := filepath.Join(dir, "pkg")
		Expect(os.MkdirAll(filepath.Join(pkgRoot, "bin"), 0o755)).To(Succeed())
		content := []byte("#!/bin/sh\necho hi\n")
		Expect(os.WriteFile(filepath.Join(pkgRoot, "bin/hi"), content, 0o755)).To(Succeed())

		active := filepath.Join(dir, "active")
		scope := Scope{ActiveRoot: active, PackageName: "hello", PackageRoot: pkgRoot}
		inv := Invocation{Action: "install", PackageName: "hello", Params: map[string]any{
			"src":    filepath.Join(pkgRoot, "bin/hi"),
			"dest":   filepath.Join(active, "hello/bin/hi"),
			"policy": "symlink",
		}}
		res, err := Install(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Expected.FileType).To(Equal("symlink"))
		Expect(res.Expected.ContentHash).To(Equal(blake3Hex(content)))
		Expect(res.Stat.Inode).NotTo(BeZero())
		Expect(res.Stat.MtimeNs).NotTo(BeZero())
	})

	It("captures expected fingerprint for policy=copy", func() {
		dir := GinkgoT().TempDir()
		pkgRoot := filepath.Join(dir, "pkg")
		Expect(os.MkdirAll(filepath.Join(pkgRoot, "bin"), 0o755)).To(Succeed())
		content := []byte("payload\n")
		Expect(os.WriteFile(filepath.Join(pkgRoot, "bin/hi"), content, 0o644)).To(Succeed())

		active := filepath.Join(dir, "active")
		scope := Scope{ActiveRoot: active, PackageName: "hello", PackageRoot: pkgRoot}
		inv := Invocation{Action: "install", PackageName: "hello", Params: map[string]any{
			"src":    filepath.Join(pkgRoot, "bin/hi"),
			"dest":   filepath.Join(active, "hello/bin/hi"),
			"policy": "copy",
		}}
		res, err := Install(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Expected.FileType).To(Equal("regular"))
		Expect(res.Expected.ContentHash).To(Equal(blake3Hex(content)))
	})

	It("rejects a dest outside scope", func() {
		dir := GinkgoT().TempDir()
		scope := Scope{
			ActiveRoot:  filepath.Join(dir, "active"),
			PackageName: "hello",
		}
		srcFile := filepath.Join(dir, "src")
		Expect(os.WriteFile(srcFile, []byte("x"), 0o644)).To(Succeed())

		inv := Invocation{
			Action:      "install",
			PackageName: "hello",
			Phase:       PhasePostPlace,
			Params: map[string]any{
				"src":    srcFile,
				"dest":   "/usr/bin/hi",
				"policy": "symlink",
			},
		}
		_, err := Install(inv, scope)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("outside"))
	})
})
