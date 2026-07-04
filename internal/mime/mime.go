// Package mime installs packages' shared-mime-info XML files into the user's
// MIME packages directory, mirroring the desktop installer. It selects mime
// ownership entries and drives internal/linkfarm against the single host mime
// packages dir, so a host .xml file is "polypkg's" iff it is a symlink into the
// active generation's mime area.
package mime

import (
	"path/filepath"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/linkfarm"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// ExposedMimeEntries returns the .xml filenames a generation installs: every
// mime-action ownership entry, parsed from its mime/<file> path. Malformed paths
// and non-component files are dropped (defense in depth).
func ExposedMimeEntries(entries []schema.OwnershipEntry) []string {
	var out []string
	for i := range entries {
		e := &entries[i]
		if e.Action != "mime" {
			continue
		}
		parts := strings.Split(e.Path, "/")
		if len(parts) != 2 || parts[0] != "mime" {
			continue
		}
		if file := parts[1]; linkfarm.IsComponent(file) {
			out = append(out, file)
		}
	}
	return out
}

// Reconcile links mimePackagesDir against the active generation's mime area
// (one linkfarm.Reconcile call): a host .xml file is polypkg's iff it is a
// symlink into activeMimeDir.
func Reconcile(mimePackagesDir, activeMimeDir string, entries []schema.OwnershipEntry) (linkfarm.Result, error) {
	want := map[string]string{}
	for _, file := range ExposedMimeEntries(entries) {
		want[file] = filepath.Join(activeMimeDir, file)
	}
	return linkfarm.Reconcile(mimePackagesDir, activeMimeDir, want)
}

// PruneAll removes every polypkg-owned .xml link from mimePackagesDir.
func PruneAll(mimePackagesDir, activeMimeDir string) ([]string, error) {
	return linkfarm.PruneAll(mimePackagesDir, activeMimeDir)
}
