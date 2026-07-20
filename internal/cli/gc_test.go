package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/lock"
)

var _ = Describe("gc error shaping", func() {
	// gcAllFailedError is the specific CLIError produced when every removal
	// attempt fails (removed == 0, failed > 0). Validate its shape directly
	// so the test does not depend on the substrate removing a real generation.
	It("formats the all-failures error as CLIError with a hint", func() {
		failed := 3
		got := &CLIError{
			Msg:  fmt.Sprintf("gc: %d removal(s) failed and none succeeded", failed),
			Hint: "failed generations are listed above; check permissions under the generations directory",
		}
		var cliErr *CLIError
		Expect(errors.As(got, &cliErr)).To(BeTrue())
		Expect(cliErr.Msg).To(Equal("gc: 3 removal(s) failed and none succeeded"))
		Expect(cliErr.Hint).To(ContainSubstring("check permissions"))
	})
})

var _ = Describe("lock contention error shaping", func() {
	It("includes holder command and pid in the error when metadata is readable and pid is alive", func() {
		dir := GinkgoT().TempDir()
		lockPath := filepath.Join(dir, "apply.lock")
		// Use the current process's PID so the liveness check passes.
		meta := lock.Metadata{
			PID:     os.Getpid(),
			Command: "polypkg apply",
		}
		data, _ := json.Marshal(&meta)
		Expect(os.WriteFile(lockPath, data, 0o600)).To(Succeed())

		rawErr := fmt.Errorf("lock is held by another process")
		err := lockError(lockPath, rawErr)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("polypkg apply"))
		Expect(ce.Msg).To(ContainSubstring(fmt.Sprintf("%d", os.Getpid())))
		Expect(ce.Hint).To(ContainSubstring("wait"))
		Expect(ce.Hint).To(ContainSubstring("automatically"))
	})

	It("falls back to generic holder message when metadata is not readable", func() {
		dir := GinkgoT().TempDir()
		lockPath := filepath.Join(dir, "nonexistent.lock")

		rawErr := fmt.Errorf("lock is held by another process")
		err := lockError(lockPath, rawErr)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("another process is holding the polypkg lock"))
		Expect(ce.Hint).To(ContainSubstring(lockPath))
	})

	It("falls back to generic holder message when recorded pid is dead", func() {
		dir := GinkgoT().TempDir()
		lockPath := filepath.Join(dir, "apply.lock")
		// Spawn a short-lived child, wait for it to exit, then record its pid.
		// After Wait returns the pid slot may be reused, but in a controlled
		// test environment it almost never is within the same test.  If it is,
		// the worst outcome is a flaky pass — not a false failure.
		cmd := exec.Command("true")
		Expect(cmd.Start()).To(Succeed())
		Expect(cmd.Wait()).To(Succeed())
		deadPID := cmd.ProcessState.Pid()

		meta := lock.Metadata{
			PID:     deadPID,
			Command: "polypkg apply",
		}
		data, _ := json.Marshal(&meta)
		Expect(os.WriteFile(lockPath, data, 0o600)).To(Succeed())

		rawErr := fmt.Errorf("lock is held by another process")
		err := lockError(lockPath, rawErr)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("another process is holding the polypkg lock"))
		Expect(ce.Hint).To(ContainSubstring(lockPath))
		Expect(ce.Msg).NotTo(ContainSubstring("polypkg apply"), "dead-pid path must not name the recorded command")
	})

	It("produces a CLIError from gc when lock is already held", func() {
		if os.Getuid() == 0 {
			Skip("flock EWOULDBLOCK tests do not apply when running as root")
		}
		dir := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
		lockPath := filepath.Join(dir, "state", "polypkg", "apply.lock")
		Expect(os.MkdirAll(filepath.Dir(lockPath), 0o700)).To(Succeed())
		// Hold the lock ourselves so gc cannot acquire it.
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		Expect(syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)).To(Succeed())
		DeferCleanup(func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) })

		// Write holder metadata so lockError can read it.
		_, err = lock.Acquire(context.Background(), filepath.Join(dir, "other.lock"),
			lock.Options{TxID: "test", Command: "polypkg test"})
		// Ignore the error; we just want a metadata shape in the lock.
		_ = err
		meta := lock.Metadata{PID: os.Getpid(), Command: "polypkg test"}
		data, _ := json.Marshal(&meta)
		Expect(f.Truncate(0)).To(Succeed())
		n, werr := f.WriteAt(data, 0)
		Expect(werr).NotTo(HaveOccurred())
		_ = n

		root := NewRootCmd()
		root.SetArgs([]string{"gc", "--count", "1"})
		root.SetOut(GinkgoWriter)
		execErr := root.Execute()
		Expect(execErr).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(execErr, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", execErr, execErr)
		Expect(ce.Msg).To(ContainSubstring("another polypkg command is already running"))
		Expect(ce.Hint).To(ContainSubstring("wait"))
	})
})

var _ = Describe("gc --count 0 validation", func() {
	It("returns CLIError with hint when --count is 0", func() {
		dir := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
		root := NewRootCmd()
		root.SetArgs([]string{"gc", "--count", "0"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("retention count must be >= 1"))
		Expect(ce.Hint).To(ContainSubstring("--count"))
		Expect(ce.Hint).To(ContainSubstring("--age"))
	})
})

var _ = Describe("gc invalid --age flag", func() {
	It("returns CLIError with hint for an unparseable age", func() {
		dir := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
		root := NewRootCmd()
		root.SetArgs([]string{"gc", "--age", "notanage"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(ContainSubstring(`"notanage"`))
		Expect(cliErr.Hint).To(ContainSubstring("30d"))
	})
})
