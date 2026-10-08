package action

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"lukechampine.com/blake3"
)

// maxScannedFD bounds fifoFDs's descriptor scan. The kernel hands out the
// lowest free number, so a test process's descriptors stay far below this.
const maxScannedFD = 4096

// fifoFDs counts the descriptors in this process that refer to the file at
// path, by matching device and inode. It avoids /proc/self/fd, which macOS
// lacks, and stays safe to call from a goroutine (no assertions).
func fifoFDs(path string) int {
	var want syscall.Stat_t
	if syscall.Stat(path, &want) != nil {
		return 0
	}
	n := 0
	for fd := range maxScannedFD {
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) == nil && st.Dev == want.Dev && st.Ino == want.Ino {
			n++
		}
	}
	return n
}

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

	It("never carries setuid, setgid or sticky from the source for policy=copy", func() {
		dir := GinkgoT().TempDir()
		srcDir := filepath.Join(dir, "store/abc-hello-1.0/content")
		Expect(os.MkdirAll(srcDir, 0o755)).To(Succeed())
		srcFile := filepath.Join(srcDir, "hi")
		Expect(os.WriteFile(srcFile, []byte("data"), 0o755)).To(Succeed())
		special := os.ModeSetuid | os.ModeSetgid | os.ModeSticky
		Expect(os.Chmod(srcFile, 0o755|special)).To(Succeed())
		srcInfo, err := os.Stat(srcFile)
		Expect(err).NotTo(HaveOccurred())
		if srcInfo.Mode()&os.ModeSetuid == 0 {
			Skip("the filesystem did not keep setuid on the source fixture")
		}

		scope := Scope{
			ActiveRoot:  filepath.Join(dir, "active"),
			PackageName: "hello",
			PackageRoot: srcDir,
		}
		dest := filepath.Join(scope.ActiveRoot, "hello", "bin", "hi")
		_, err = Install(Invocation{
			Action:      "install",
			PackageName: "hello",
			Phase:       PhasePostPlace,
			Params: map[string]any{
				"src":    srcFile,
				"dest":   dest,
				"policy": "copy",
			},
		}, scope)
		Expect(err).NotTo(HaveOccurred())

		info, err := os.Lstat(dest)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode()&special).To(BeZero(), "a copied file must not inherit setuid, setgid or sticky")
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

	It("copies by default: an executable file that a later source edit cannot change", func() {
		dir := GinkgoT().TempDir()
		pkgRoot := filepath.Join(dir, "pkg")
		Expect(os.MkdirAll(filepath.Join(pkgRoot, "bin"), 0o755)).To(Succeed())
		src := filepath.Join(pkgRoot, "bin/hi")
		content := []byte("#!/bin/sh\necho hi\n")
		Expect(os.WriteFile(src, content, 0o755)).To(Succeed())

		active := filepath.Join(dir, "active")
		scope := Scope{ActiveRoot: active, PackageName: "hello", PackageRoot: pkgRoot}
		dest := filepath.Join(active, "hello/bin/hi")
		res, err := Install(Invocation{Action: "install", PackageName: "hello", Params: map[string]any{
			"src":  src,
			"dest": dest,
		}}, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Expected.FileType).To(Equal("regular"))
		Expect(res.Expected.ContentHash).To(Equal(blake3Hex(content)))

		info, err := os.Lstat(dest)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().IsRegular()).To(BeTrue(), "the default must not link into the package's files")
		Expect(info.Mode().Perm()&0o100).NotTo(BeZero(), "an executable must stay executable")

		// The extract cache is user-writable: editing it must not reach the
		// installed command.
		Expect(os.WriteFile(src, []byte("#!/bin/sh\necho tampered\n"), 0o755)).To(Succeed())
		got, err := os.ReadFile(dest)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(content))
	})

	It("records the hash of the bytes it copied, even if the source changes afterwards", func() {
		// A FIFO source hands each open whatever the next writer sends, so it
		// models a source edited between the copy and any later re-read.
		dir := GinkgoT().TempDir()
		pkgRoot := filepath.Join(dir, "pkg")
		Expect(os.MkdirAll(pkgRoot, 0o755)).To(Succeed())
		src := filepath.Join(pkgRoot, "payload")
		Expect(syscall.Mkfifo(src, 0o644)).To(Succeed())

		copied, later := []byte("copied bytes\n"), []byte("edited afterwards\n")
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			// fdCount polls until cond holds for the FIFO's descriptor count,
			// giving up after 5s. Giving up returns the goroutine, whose
			// closed writer fd then gives Install's read an EOF: a failed
			// spec instead of a read that blocks until go test's timeout.
			fdCount := func(cond func(int) bool) bool {
				giveUp := time.Now().Add(5 * time.Second)
				for !cond(fifoFDs(src)) {
					if time.Now().After(giveUp) {
						return false
					}
					time.Sleep(time.Millisecond)
				}
				return true
			}
			for _, body := range [][]byte{copied, later} {
				deadline := time.Now().Add(500 * time.Millisecond)
				for {
					// Non-blocking open succeeds only once a reader is waiting.
					fd, err := syscall.Open(src, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
					if err == nil {
						// The reader counts as waiting while still inside
						// open(2); hold on until its fd exists, write, close,
						// then wait for it to close, so the next body can only
						// reach a later open, never this reader's stream.
						if !fdCount(func(n int) bool { return n >= 2 }) {
							_ = syscall.Close(fd)
							return
						}
						_, _ = syscall.Write(fd, body)
						_ = syscall.Close(fd)
						if !fdCount(func(n int) bool { return n == 0 }) {
							return
						}
						break
					}
					if !errors.Is(err, syscall.ENXIO) || time.Now().After(deadline) {
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
		}()

		active := filepath.Join(dir, "active")
		scope := Scope{ActiveRoot: active, PackageName: "hello", PackageRoot: pkgRoot}
		dest := filepath.Join(active, "hello/payload")
		res, err := Install(Invocation{Action: "install", PackageName: "hello", Params: map[string]any{
			"src": src, "dest": dest, "policy": "copy",
		}}, scope)
		Expect(err).NotTo(HaveOccurred())
		Eventually(done, 5*time.Second).Should(BeClosed())

		installed, err := os.ReadFile(dest)
		Expect(err).NotTo(HaveOccurred())
		Expect(installed).To(Equal(copied))
		Expect(res.Expected.ContentHash).To(Equal(blake3Hex(installed)),
			"the recorded hash must describe the installed file, not a later read of the source")
	})
})
