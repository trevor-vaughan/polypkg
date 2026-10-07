//go:build !linux

package substrate

import (
	"errors"
	"os"
)

// defaultSyncfs is never called off Linux; syncPayload walks instead. It
// exists so OwnStore's syncfs field has one default on every platform.
func defaultSyncfs(*os.File) error {
	return errors.New("syncfs is only available on linux")
}

// syncPayload makes everything placed under dir durable by fsyncing each file
// and directory: there is no portable single-call equivalent of syncfs(2).
func (s *OwnStore) syncPayload(dir string) error {
	return s.syncTreeWalk(dir)
}
