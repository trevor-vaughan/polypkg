// Package desktop installs packages' .desktop application entries into the
// user's applications directory, mirroring the ~/.local/bin bridge. It selects
// desktop ownership entries and drives internal/linkfarm against the single host
// applications dir, so a host .desktop file is "polypkg's" iff it is a symlink
// into the active generation's applications area.
package desktop

import (
	"path/filepath"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/linkfarm"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// ExposedDesktopEntries returns the .desktop filenames a generation installs:
// every desktop-action ownership entry, parsed from its applications/<file> path.
// Malformed paths and non-component files are dropped (defense in depth).
func ExposedDesktopEntries(entries []schema.OwnershipEntry) []string {
	var out []string
	for i := range entries {
		e := &entries[i]
		if e.Action != "desktop" {
			continue
		}
		parts := strings.Split(e.Path, "/")
		if len(parts) != 2 || parts[0] != "applications" {
			continue
		}
		if file := parts[1]; linkfarm.IsComponent(file) {
			out = append(out, file)
		}
	}
	return out
}

// Reconcile links applicationsDir against the active generation's applications
// area (one linkfarm.Reconcile call): a host .desktop file is polypkg's iff it
// is a symlink into activeDesktopDir.
func Reconcile(applicationsDir, activeDesktopDir string, entries []schema.OwnershipEntry) (linkfarm.Result, error) {
	want := map[string]string{}
	for _, file := range ExposedDesktopEntries(entries) {
		want[file] = filepath.Join(activeDesktopDir, file)
	}
	return linkfarm.Reconcile(applicationsDir, activeDesktopDir, want)
}

// PruneAll removes every polypkg-owned .desktop link from applicationsDir.
func PruneAll(applicationsDir, activeDesktopDir string) ([]string, error) {
	return linkfarm.PruneAll(applicationsDir, activeDesktopDir)
}
