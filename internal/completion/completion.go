// Package completion installs packages' shell-completion scripts into the
// user's per-shell completion directories, mirroring the ~/.local/bin bridge.
// It selects completion ownership entries and drives internal/linkfarm once per
// shell, so a host completion file is "polypkg's" iff it is a symlink into the
// active generation's completions/<shell> area.
package completion

import (
	"path/filepath"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/linkfarm"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// Want is one installed completion: its shell and the on-disk file name the
// shell loads (e.g. {bash, rg}, {zsh, _rg}, {fish, rg.fish}).
type Want struct {
	Shell    string
	HostFile string
}

// ExposedCompletions returns the completions a generation installs: every
// ownership entry from the completion action, parsed from its
// completions/<shell>/<hostfile> path. Malformed paths and non-component host
// files are dropped (defense in depth; the action only writes well-formed paths).
func ExposedCompletions(entries []schema.OwnershipEntry) []Want {
	var out []Want
	for i := range entries {
		e := &entries[i]
		if e.Action != "completion" {
			continue
		}
		parts := strings.Split(e.Path, "/")
		if len(parts) != 3 || parts[0] != "completions" {
			continue
		}
		shell, hostFile := parts[1], parts[2]
		if shell == "" || !linkfarm.IsComponent(hostFile) {
			continue
		}
		out = append(out, Want{Shell: shell, HostFile: hostFile})
	}
	return out
}

// Reconcile links each shell's host dir (hostDirs[shell]) against the active
// generation's completions/<shell> area, returning the per-shell linkfarm
// result. Wants for a shell with no host dir configured are skipped. Shells with
// no wants are still reconciled (to prune stale ours-links) when a host dir is
// configured for them.
func Reconcile(hostDirs map[string]string, activeCompletionsDir string, want []Want) (map[string]linkfarm.Result, error) {
	byShell := map[string]map[string]string{}
	for shell := range hostDirs {
		byShell[shell] = map[string]string{}
	}
	for _, w := range want {
		m, ok := byShell[w.Shell]
		if !ok {
			continue // no host dir for this shell
		}
		m[w.HostFile] = filepath.Join(activeCompletionsDir, w.Shell, w.HostFile)
	}
	out := map[string]linkfarm.Result{}
	for shell, dir := range hostDirs {
		ownedDir := filepath.Join(activeCompletionsDir, shell)
		res, err := linkfarm.Reconcile(dir, ownedDir, byShell[shell])
		if err != nil {
			return out, err
		}
		out[shell] = res
	}
	return out, nil
}

// PruneAll removes every polypkg-owned completion link from each configured host
// dir, returning the pruned names per shell.
func PruneAll(hostDirs map[string]string, activeCompletionsDir string) (map[string][]string, error) {
	out := map[string][]string{}
	for shell, dir := range hostDirs {
		pruned, err := linkfarm.PruneAll(dir, filepath.Join(activeCompletionsDir, shell))
		if err != nil {
			return out, err
		}
		if len(pruned) > 0 {
			out[shell] = pruned
		}
	}
	return out, nil
}
