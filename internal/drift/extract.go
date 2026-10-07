package drift

import (
	"fmt"
	"os"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// inspectExtract checks one path an extract action placed. The entry records
// the shape of what was placed, so it is checked by that shape's rule: a
// directory by type and mode, a symlink by type and target, and a regular file
// by type and content (with the same unchanged-stat shortcut install uses),
// then by mode.
func inspectExtract(root *os.Root, e schema.OwnershipEntry, info os.FileInfo) (*Entry, error) {
	switch e.Expected.FileType {
	case "dir":
		return inspectDir(e, info), nil
	case "symlink":
		return inspectSymlink(root, e, info)
	}
	d, err := inspectInstall(root, e, info)
	if d != nil || err != nil {
		return d, err
	}
	if obs := fmt.Sprintf("%#o", info.Mode().Perm()); e.Expected.Mode != "" && obs != e.Expected.Mode {
		return &Entry{Owned: e, Reason: ReasonMode, Observed: obs}, nil
	}
	return nil, nil
}
