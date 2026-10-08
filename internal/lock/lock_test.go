package lock

import (
	"context"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Acquire", func() {
	It("acquires and releases when the lock is free", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "test.lock")

		l, err := Acquire(context.Background(), path, Options{})
		Expect(err).NotTo(HaveOccurred())
		Expect(l).NotTo(BeNil())
		Expect(l.Release()).To(Succeed())
	})

	It("fails fast when the lock is held", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "test.lock")

		l1, err := Acquire(context.Background(), path, Options{})
		Expect(err).NotTo(HaveOccurred())
		defer l1.Release() //nolint:errcheck

		_, err = Acquire(context.Background(), path, Options{})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("lock"))
	})

	It("waits for the holder to release when Wait is set", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "test.lock")

		l1, err := Acquire(context.Background(), path, Options{})
		Expect(err).NotTo(HaveOccurred())

		var l2 *Lock
		var l2err error
		done := make(chan struct{})
		go func() {
			defer close(done)
			l2, l2err = Acquire(context.Background(), path, Options{Wait: true})
		}()

		// The waiter must stay blocked while l1 is held: returning early (with
		// or without the lock) is exactly the bug this spec exists to catch.
		Consistently(done, "200ms", "10ms").ShouldNot(BeClosed(),
			"Acquire with Wait returned while the lock was still held")
		Expect(l1.Release()).To(Succeed())

		// Generous timeout: see the cancellation spec below.
		Eventually(done, "5s").Should(BeClosed())
		Expect(l2err).NotTo(HaveOccurred())
		Expect(l2).NotTo(BeNil())
		Expect(l2.Release()).To(Succeed())
	})

	It("times out waiting when WaitTimeout elapses and the lock stays held", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "test.lock")

		l1, err := Acquire(context.Background(), path, Options{})
		Expect(err).NotTo(HaveOccurred())
		defer l1.Release() //nolint:errcheck

		start := time.Now()
		_, err = Acquire(context.Background(), path, Options{Wait: true, WaitTimeout: 100 * time.Millisecond})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("timed out"))
		// It must have actually waited roughly the timeout, not returned early.
		Expect(time.Since(start)).To(BeNumerically(">=", 90*time.Millisecond))
	})

	It("returns when the context is cancelled while waiting", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "test.lock")

		l1, err := Acquire(context.Background(), path, Options{})
		Expect(err).NotTo(HaveOccurred())
		defer l1.Release() //nolint:errcheck

		ctx, cancel := context.WithCancel(context.Background())
		var waitErr error
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, waitErr = Acquire(ctx, path, Options{Wait: true})
		}()

		// The waiter must still be blocked before the cancel, or the
		// "cancelled" error below would not prove cancellation released it.
		Consistently(done, "200ms", "10ms").ShouldNot(BeClosed(),
			"Acquire with Wait returned before the context was cancelled")
		cancel()

		// Generous timeout: cancellation is detected on the next poll (tens of
		// ms), but the default 1s Eventually can be starved under -race + full
		// suite CPU contention.
		Eventually(done, "5s").Should(BeClosed())
		Expect(waitErr).To(HaveOccurred())
		Expect(waitErr.Error()).To(ContainSubstring("cancelled"))
	})

	It("is safe to release twice", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "test.lock")

		l, err := Acquire(context.Background(), path, Options{})
		Expect(err).NotTo(HaveOccurred())
		Expect(l.Release()).To(Succeed())
		// A second release is a no-op (the file handle was cleared).
		Expect(l.Release()).To(Succeed())
	})

	It("records TxID and Command metadata on the lock file", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "test.lock")

		l, err := Acquire(context.Background(), path, Options{
			TxID:    "tx-test",
			Command: "polypkg apply",
		})
		Expect(err).NotTo(HaveOccurred())
		defer l.Release() //nolint:errcheck

		meta, err := ReadMetadata(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(meta.TxID).To(Equal("tx-test"))
		Expect(meta.Command).To(Equal("polypkg apply"))
	})
})

var _ = Describe("ReadMetadata", func() {
	It("errors when the lock file does not exist", func() {
		_, err := ReadMetadata(filepath.Join(GinkgoT().TempDir(), "absent.lock"))
		Expect(err).To(HaveOccurred())
	})

	It("errors when the lock file is not valid JSON", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "corrupt.lock")
		Expect(os.WriteFile(path, []byte("{not valid json"), 0o600)).To(Succeed())

		_, err := ReadMetadata(path)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unmarshal"))
	})
})
