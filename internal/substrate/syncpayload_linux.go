//go:build linux

package substrate

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// defaultSyncfs flushes the whole filesystem containing f with syncfs(2):
// one syscall, independent of how many files a generation placed. It flushes
// every dirty page on that filesystem, not only the generation's, so an apply
// also waits for unrelated pending writes. syncfs reports writeback errors only
// on Linux 5.8 and later; an older kernel can return success after a failed
// writeback.
func defaultSyncfs(f *os.File) error {
	return unix.Syncfs(int(f.Fd())) //nolint:gosec // G115: an open fd always fits in int
}

// syncPayload makes everything placed under dir durable. On Linux that is a
// single syncfs of the filesystem holding dir. That also covers the metadata
// files CommitGeneration fsyncs one by one before calling this: those per-file
// fsyncs are what make the metadata durable on the non-Linux path.
func (s *OwnStore) syncPayload(dir string) error {
	f, err := os.Open(dir) //nolint:gosec // dir is the store's own generation payload directory
	if err != nil {
		return fmt.Errorf("open %s for syncfs: %w", dir, err)
	}
	defer func() { _ = f.Close() }()
	if err := s.syncfs(f); err != nil {
		return fmt.Errorf("syncfs %s: %w", dir, err)
	}
	return nil
}
