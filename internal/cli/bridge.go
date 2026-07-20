package cli

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/bridge"
	"github.com/trevor-vaughan/polypkg/internal/completion"
	"github.com/trevor-vaughan/polypkg/internal/desktop"
	"github.com/trevor-vaughan/polypkg/internal/mime"
	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// writeBridgeSummary renders a bridge.Result for text output, plus a one-line
// $PATH nudge when commands were linked into a dir not on $PATH.
func writeBridgeSummary(w *bytes.Buffer, res bridge.Result, binDir string) {
	if len(res.Linked) > 0 {
		fmt.Fprintf(w, "linked %d command(s) into %s: %s\n",
			len(res.Linked), tildeDir(binDir), strings.Join(res.Linked, ", "))
	}
	if len(res.Pruned) > 0 {
		fmt.Fprintf(w, "unlinked %d removed command(s): %s\n",
			len(res.Pruned), strings.Join(res.Pruned, ", "))
	}
	if len(res.Skipped) > 0 {
		fmt.Fprintf(w, "skipped %d (already exist, not created by polypkg): %s\n",
			len(res.Skipped), strings.Join(skippedNames(res), ", "))
	}
	if len(res.Linked) > 0 && !dirOnPath(binDir) {
		fmt.Fprintf(w, "note: %s is not on your $PATH; add it so these commands are found.\n", tildeDir(binDir))
	}
}

func dirOnPath(dir string) bool {
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if p == dir {
			return true
		}
	}
	return false
}

func tildeDir(dir string) string {
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(dir, home+string(os.PathSeparator)) {
		return "~" + strings.TrimPrefix(dir, home)
	}
	return dir
}

func skippedNames(res bridge.Result) []string {
	names := make([]string, len(res.Skipped))
	for i, c := range res.Skipped {
		names[i] = c.Name
	}
	return names
}

// bridgeBinDir returns the bin directory the bridge should manage for the scope,
// or "" when disabled (bridge.enabled). System scope resolves <prefix>/usr/local/bin;
// user scope ~/.local/bin (paths.UserBinHome).
func bridgeBinDir(scope, prefix string) (string, error) {
	ok, err := scopeConfigEnabled(scope, prefix, "bridge.enabled")
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	if scope == "system" {
		return filepath.Join(prefix, paths.SystemBinDir()), nil
	}
	return paths.UserBinHome()
}

// runBridgeReconcile performs a best-effort bridge reconcile for the live
// generation. It returns the result, the resolved bin dir, and whether anything
// ran (false when disabled, no current generation, or on a non-fatal error,
// which it logs). A bridge failure never changes the command's exit status.
func runBridgeReconcile(sub substrate.Substrate, scope, prefix string) (res bridge.Result, binDir string, ran bool) {
	var err error
	binDir, err = bridgeBinDir(scope, prefix)
	if err != nil {
		slog.Warn("bridge skipped: could not resolve bin dir or config", "error", err)
		return bridge.Result{}, "", false
	}
	if binDir == "" {
		return bridge.Result{}, "", false // disabled
	}
	if scope == "system" {
		// Pre-create at the scope dir mode (0o755 for system, traversable) before
		// linkfarm would create it 0o750; linkfarm's MkdirAll then no-ops on the
		// existing dir. Under a system apply's pinned 0o022 umask this lands
		// exactly 0o755. Using scopeDirMode keeps it tied to SP1's scope-mode
		// source of truth (and is a variable, so gosec G301 is satisfied).
		if err := os.MkdirAll(binDir, scopeDirMode(scope)); err != nil {
			slog.Warn("bridge skipped: could not create system bin dir", "error", err)
			return bridge.Result{}, "", false
		}
	}
	own, _, _, err := sub.CurrentOwnership()
	if err != nil {
		return bridge.Result{}, "", false
	}
	res, err = bridge.Reconcile(binDir, sub.ActiveBinDir(), bridge.ExposedCommands(own.Entries))
	if err != nil {
		slog.Warn("bridge reconcile failed; commands may not be on PATH", "error", err)
		return bridge.Result{}, "", false
	}
	return res, binDir, true
}

func newLinkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "link",
		Short: "Symlink the current generation's commands into ~/.local/bin",
		Long: "polypkg keeps the current generation's commands on your $PATH by symlinking them " +
			"into ~/.local/bin (user scope) or /usr/local/bin (system scope). apply does this " +
			"automatically; link re-runs the reconcile if links are missing or stale.\n\n" +
			"~/.local/bin must be on your $PATH.",
		Example: "  polypkg link",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "link", runLink(cmd, format))
		},
	}
}

func runLink(cmd *cobra.Command, format Format) error {
	dataHome, err := paths.UserDataHome()
	if err != nil {
		return err
	}
	binDir, err := paths.UserBinHome()
	if err != nil {
		return err
	}
	sub, err := substrate.NewOwnStore(dataHome)
	if err != nil {
		return err
	}
	own, _, _, err := sub.CurrentOwnership()
	if err != nil {
		return &CLIError{
			Msg:  "no generation has been applied yet",
			Hint: "run `polypkg apply` first",
			Err:  err,
		}
	}
	res, err := bridge.Reconcile(binDir, sub.ActiveBinDir(), bridge.ExposedCommands(own.Entries))
	if err != nil {
		return fmt.Errorf("bridge: %w", err)
	}
	compRes, compDirs, comped := runCompletionReconcile(sub, "user", "")
	deskRes, deskDir, desked := runDesktopReconcile(sub, "user", "")
	mimeRes, mimeDir, mimed := runMimeReconcile(sub, "user", "")
	EmitResult(cmd, format, "link",
		map[string]any{"linked": res.Linked, "pruned": res.Pruned, "skipped": skippedNames(res)},
		func(w *bytes.Buffer, _ map[string]any) {
			if len(res.Linked) == 0 && len(res.Pruned) == 0 && len(res.Skipped) == 0 {
				fmt.Fprintf(w, "%s already up to date\n", tildeDir(binDir))
			} else {
				writeBridgeSummary(w, res, binDir)
			}
			if comped {
				writeCompletionSummary(w, compRes, compDirs)
			}
			if desked {
				writeDesktopSummary(w, deskRes, deskDir)
			}
			if mimed {
				writeMimeSummary(w, mimeRes, mimeDir)
			}
		})
	return nil
}

func newUnlinkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unlink",
		Short: "Remove all polypkg-created command links from ~/.local/bin",
		Long: "Removes every command symlink polypkg created in the bin directory. " +
			"It does not remove the installed packages themselves, only the $PATH links.",
		Example: "  polypkg unlink",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "unlink", runUnlink(cmd, format))
		},
	}
}

func runUnlink(cmd *cobra.Command, format Format) error {
	dataHome, err := paths.UserDataHome()
	if err != nil {
		return err
	}
	binDir, err := paths.UserBinHome()
	if err != nil {
		return err
	}
	sub, err := substrate.NewOwnStore(dataHome)
	if err != nil {
		return err
	}
	pruned, err := bridge.PruneAll(binDir, sub.ActiveBinDir())
	if err != nil {
		return fmt.Errorf("bridge: %w", err)
	}
	hostDirs, herr := completionHostDirs("user", "")
	var compPruned map[string][]string
	if herr == nil && hostDirs != nil {
		var perr error
		if compPruned, perr = completion.PruneAll(hostDirs, sub.ActiveCompletionsDir()); perr != nil {
			slog.Warn("completion prune failed; some completion links may remain", "error", perr)
		}
	}
	appsDir, derr := desktopApplicationsDir("user", "")
	var deskPruned []string
	if derr == nil && appsDir != "" {
		var perr error
		if deskPruned, perr = desktop.PruneAll(appsDir, sub.ActiveDesktopDir()); perr != nil {
			slog.Warn("desktop prune failed; some desktop links may remain", "error", perr)
		}
	}
	mimeDir, merr := mimePackagesDir("user", "")
	var mimePruned []string
	if merr == nil && mimeDir != "" {
		var perr error
		if mimePruned, perr = mime.PruneAll(mimeDir, sub.ActiveMimeDir()); perr != nil {
			slog.Warn("mime prune failed; some MIME package links may remain", "error", perr)
		}
	}
	EmitResult(cmd, format, "unlink",
		map[string]any{"pruned": pruned},
		func(w *bytes.Buffer, _ map[string]any) {
			if len(pruned) == 0 && len(compPruned) == 0 && len(deskPruned) == 0 && len(mimePruned) == 0 {
				fmt.Fprintln(w, "no polypkg links to remove")
				return
			}
			if len(pruned) > 0 {
				fmt.Fprintf(w, "removed %d command link(s) from %s: %s\n",
					len(pruned), tildeDir(binDir), strings.Join(pruned, ", "))
			}
			for _, shell := range sortedShellKeys(compPruned) {
				fmt.Fprintf(w, "removed %d %s completion link(s): %s\n",
					len(compPruned[shell]), shell, strings.Join(compPruned[shell], ", "))
			}
			if len(deskPruned) > 0 {
				fmt.Fprintf(w, "removed %d desktop file(s): %s\n",
					len(deskPruned), strings.Join(deskPruned, ", "))
			}
			if len(mimePruned) > 0 {
				fmt.Fprintf(w, "removed %d MIME package(s): %s\n",
					len(mimePruned), strings.Join(mimePruned, ", "))
			}
		})
	return nil
}

// sortedShellKeys returns the shells in m, sorted, for deterministic output.
func sortedShellKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
