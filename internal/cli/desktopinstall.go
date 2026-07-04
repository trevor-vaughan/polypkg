package cli

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/desktop"
	"github.com/trevor-vaughan/polypkg/internal/linkfarm"
	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// desktopApplicationsDir returns the applications dir for the scope, or "" when
// desktop install is disabled via config (desktop.enabled, default true;
// POLYPKG_DESKTOP_ENABLED overrides). System scope resolves <prefix>/usr/local/share/applications;
// user scope resolves the XDG applications dir.
func desktopApplicationsDir(scope, prefix string) (string, error) {
	ok, err := scopeConfigEnabled(scope, prefix, "desktop.enabled")
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	if scope == "system" {
		return filepath.Join(prefix, paths.SystemApplicationsDir()), nil
	}
	return paths.UserApplicationsDir()
}

// runDesktopReconcile installs the live generation's .desktop entries into the
// applications dir for the scope, best-effort. ran is false when disabled, no
// current generation, or on a non-fatal error (logged). Never changes exit status.
func runDesktopReconcile(sub substrate.Substrate, scope, prefix string) (res linkfarm.Result, dir string, ran bool) {
	appsDir, err := desktopApplicationsDir(scope, prefix)
	if err != nil {
		slog.Warn("desktop skipped: could not resolve dir or config", "error", err)
		return linkfarm.Result{}, "", false
	}
	if appsDir == "" {
		return linkfarm.Result{}, "", false // disabled
	}
	if scope == "system" {
		if err := os.MkdirAll(appsDir, scopeDirMode(scope)); err != nil {
			slog.Warn("desktop skipped: could not create system applications dir", "error", err)
			return linkfarm.Result{}, "", false
		}
	}
	own, _, _, err := sub.CurrentOwnership()
	if err != nil {
		return linkfarm.Result{}, "", false
	}
	r, err := desktop.Reconcile(appsDir, sub.ActiveDesktopDir(), own.Entries)
	if err != nil {
		slog.Warn("desktop reconcile failed; menu entries may be stale", "error", err)
		return linkfarm.Result{}, "", false
	}
	return r, appsDir, true
}

// writeDesktopSummary renders installed/removed .desktop counts. No nudge — the
// applications dir is auto-discovered by the desktop environment.
func writeDesktopSummary(w *bytes.Buffer, res linkfarm.Result, dir string) {
	if len(res.Linked) > 0 {
		fmt.Fprintf(w, "installed %d desktop file(s) into %s: %s\n",
			len(res.Linked), tildeDir(dir), strings.Join(res.Linked, ", "))
	}
	if len(res.Pruned) > 0 {
		fmt.Fprintf(w, "removed %d desktop file(s): %s\n",
			len(res.Pruned), strings.Join(res.Pruned, ", "))
	}
	if len(res.Skipped) > 0 {
		fmt.Fprintf(w, "skipped %d desktop file(s) (already exist, not created by polypkg): %s\n",
			len(res.Skipped), strings.Join(skippedNames(res), ", "))
	}
}
