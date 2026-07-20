package cli

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/linkfarm"
	"github.com/trevor-vaughan/polypkg/internal/mime"
	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// mimePackagesDir returns the mime packages dir for the scope, or "" when mime
// install is disabled via config (mime.enabled, default true; POLYPKG_MIME_ENABLED
// overrides). System scope resolves <prefix>/usr/local/share/mime/packages;
// user scope resolves the XDG mime packages dir.
func mimePackagesDir(scope, prefix string) (string, error) {
	ok, err := scopeConfigEnabled(scope, prefix, "mime.enabled")
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	if scope == "system" {
		return filepath.Join(prefix, paths.SystemMimePackagesDir()), nil
	}
	return paths.UserMimePackagesDir()
}

// runMimeReconcile installs the live generation's shared-mime-info entries into
// the mime packages dir for the scope, best-effort. ran is false when disabled,
// no current generation, or on a non-fatal error (logged). Never changes exit status.
func runMimeReconcile(sub substrate.Substrate, scope, prefix string) (res linkfarm.Result, dir string, ran bool) {
	mimeDir, err := mimePackagesDir(scope, prefix)
	if err != nil {
		slog.Warn("mime skipped: could not resolve dir or config", "error", err)
		return linkfarm.Result{}, "", false
	}
	if mimeDir == "" {
		return linkfarm.Result{}, "", false // disabled
	}
	if scope == "system" {
		if err := os.MkdirAll(mimeDir, scopeDirMode(scope)); err != nil {
			slog.Warn("mime skipped: could not create system mime dir", "error", err)
			return linkfarm.Result{}, "", false
		}
	}
	own, _, _, err := sub.CurrentOwnership()
	if err != nil {
		return linkfarm.Result{}, "", false
	}
	r, err := mime.Reconcile(mimeDir, sub.ActiveMimeDir(), own.Entries)
	if err != nil {
		slog.Warn("mime reconcile failed; MIME associations may be stale", "error", err)
		return linkfarm.Result{}, "", false
	}
	return r, mimeDir, true
}

// writeMimeSummary renders installed/removed/skipped MIME-package counts. When
// anything changed, it nudges the user to rebuild the MIME caches: unlike
// desktop menu entries (auto-rescanned), MIME associations need
// update-mime-database to take effect, and polypkg does not exec host tools.
func writeMimeSummary(w *bytes.Buffer, res linkfarm.Result, dir string) {
	if len(res.Linked) > 0 {
		fmt.Fprintf(w, "installed %d MIME package(s) into %s: %s\n",
			len(res.Linked), tildeDir(dir), strings.Join(res.Linked, ", "))
	}
	if len(res.Pruned) > 0 {
		fmt.Fprintf(w, "removed %d MIME package(s): %s\n",
			len(res.Pruned), strings.Join(res.Pruned, ", "))
	}
	if len(res.Skipped) > 0 {
		fmt.Fprintf(w, "skipped %d MIME package(s) (already exist, not created by polypkg): %s\n",
			len(res.Skipped), strings.Join(skippedNames(res), ", "))
	}
	if len(res.Linked) > 0 || len(res.Pruned) > 0 {
		fmt.Fprintf(w, "note: run 'update-mime-database %s' to refresh the MIME cache.\n",
			tildeDir(filepath.Dir(dir)))
	}
}
