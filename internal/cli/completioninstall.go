package cli

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/completion"
	"github.com/trevor-vaughan/polypkg/internal/linkfarm"
	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// completionHostDirs resolves the per-shell completion directories for the scope,
// or nil when completion install is disabled via config (completion.enabled,
// default true; POLYPKG_COMPLETION_ENABLED overrides). System scope resolves
// <prefix>/usr/local/share/…; user scope resolves the XDG shell dirs.
func completionHostDirs(scope, prefix string) (map[string]string, error) {
	ok, err := scopeConfigEnabled(scope, prefix, "completion.enabled")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	if scope == "system" {
		return map[string]string{
			"bash": filepath.Join(prefix, paths.SystemBashCompletionDir()),
			"zsh":  filepath.Join(prefix, paths.SystemZshCompletionDir()),
			"fish": filepath.Join(prefix, paths.SystemFishCompletionDir()),
		}, nil
	}
	bash, err := paths.UserBashCompletionDir()
	if err != nil {
		return nil, err
	}
	zsh, err := paths.UserZshCompletionDir()
	if err != nil {
		return nil, err
	}
	fish, err := paths.UserFishCompletionDir()
	if err != nil {
		return nil, err
	}
	return map[string]string{"bash": bash, "zsh": zsh, "fish": fish}, nil
}

// runCompletionReconcile installs the live generation's completions into the
// shell dirs for the scope, best-effort. It returns the per-shell result, the
// resolved host dirs, and whether anything ran (false when disabled, no current
// generation, or on a non-fatal error, which it logs). A failure never changes
// the command's exit status.
func runCompletionReconcile(sub substrate.Substrate, scope, prefix string) (res map[string]linkfarm.Result, hostDirs map[string]string, ran bool) {
	var err error
	hostDirs, err = completionHostDirs(scope, prefix)
	if err != nil {
		slog.Warn("completion skipped: could not resolve dirs or config", "error", err)
		return nil, nil, false
	}
	if hostDirs == nil {
		return nil, nil, false // disabled
	}
	if scope == "system" {
		for _, d := range hostDirs {
			if err := os.MkdirAll(d, scopeDirMode(scope)); err != nil {
				slog.Warn("completion skipped: could not create system completion dir", "error", err)
				return nil, nil, false
			}
		}
	}
	own, _, _, err := sub.CurrentOwnership()
	if err != nil {
		return nil, nil, false
	}
	res, err = completion.Reconcile(hostDirs, sub.ActiveCompletionsDir(), completion.ExposedCompletions(own.Entries))
	if err != nil {
		slog.Warn("completion reconcile failed; shell completions may be stale", "error", err)
		return nil, nil, false
	}
	return res, hostDirs, true
}

// completionResultData renders a per-shell reconcile result as JSON-friendly
// data (each shell -> {linked, pruned}), for the machine-readable output of
// apply/rollback, mirroring the bridge's data block.
func completionResultData(res map[string]linkfarm.Result) map[string]any {
	out := make(map[string]any, len(res))
	for shell, r := range res {
		out[shell] = map[string]any{"linked": r.Linked, "pruned": r.Pruned}
	}
	return out
}

// writeCompletionSummary renders per-shell linked/pruned completion counts and a
// one-time zsh $fpath nudge when zsh completions were linked.
func writeCompletionSummary(w *bytes.Buffer, res map[string]linkfarm.Result, hostDirs map[string]string) {
	shells := make([]string, 0, len(res))
	for s := range res {
		shells = append(shells, s)
	}
	sort.Strings(shells)
	for _, shell := range shells {
		r := res[shell]
		if len(r.Linked) > 0 {
			fmt.Fprintf(w, "installed %d %s completion(s): %s\n", len(r.Linked), shell, strings.Join(r.Linked, ", "))
		}
		if len(r.Pruned) > 0 {
			fmt.Fprintf(w, "removed %d %s completion(s): %s\n", len(r.Pruned), shell, strings.Join(r.Pruned, ", "))
		}
	}
	if zsh, ok := res["zsh"]; ok && len(zsh.Linked) > 0 {
		fmt.Fprintf(w, "note: add %s to your $fpath before compinit to use zsh completions.\n", hostDirs["zsh"])
	}
}
