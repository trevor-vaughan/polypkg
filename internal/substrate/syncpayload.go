package substrate

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// syncTreeWalk fsyncs every regular file and directory under dir, dir
// included, through s.fsync. Symlinks are not followed: the directory entry
// holding a symlink is synced with its directory. It is the portable way to
// make a placed package payload durable, and the fallback where syncfs(2) is
// unavailable.
func (s *OwnStore) syncTreeWalk(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}
		f, err := os.Open(p) //nolint:gosec // p is under the store's own generation directory
		if err != nil {
			return fmt.Errorf("open %s for fsync: %w", p, err)
		}
		syncErr := s.fsync(f)
		closeErr := f.Close()
		if syncErr != nil {
			return fmt.Errorf("fsync %s: %w", p, syncErr)
		}
		return closeErr
	})
}
