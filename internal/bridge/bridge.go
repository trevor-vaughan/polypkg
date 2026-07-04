// Package bridge reconciles the user's ~/.local/bin against the commands a
// polypkg generation exposes, so installed commands are runnable without manual
// $PATH editing. A bin-dir entry is "polypkg's" iff it is a symlink whose target
// is <activeBinDir>/<name>. The conflict-safe reconcile lives in internal/linkfarm;
// this package only selects the command set and adapts it to linkfarm.
package bridge

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/linkfarm"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// Result is linkfarm's reconcile result, re-exported so existing callers keep
// using bridge.Result.
type Result = linkfarm.Result

// Conflict is linkfarm's collision record, re-exported so existing callers keep
// using bridge.Conflict.
type Conflict = linkfarm.Conflict

// ExposedCommands returns the sorted, unique command names a generation puts on
// PATH: every ownership entry that places a shared bin/<name> link (the path and
// alternatives actions).
func ExposedCommands(entries []schema.OwnershipEntry) []string {
	set := map[string]bool{}
	for i := range entries {
		e := &entries[i]
		if (e.Action == "path" || e.Action == "alternatives") && strings.HasPrefix(e.Path, "bin/") {
			if name := strings.TrimPrefix(e.Path, "bin/"); linkfarm.IsComponent(name) {
				set[name] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Reconcile makes binDir hold polypkg's links for want (each ->
// <activeBinDir>/<name>), delegating to linkfarm.
func Reconcile(binDir, activeBinDir string, want []string) (Result, error) {
	m := make(map[string]string, len(want))
	for _, n := range want {
		m[n] = filepath.Join(activeBinDir, n)
	}
	return linkfarm.Reconcile(binDir, activeBinDir, m)
}

// PruneAll removes every polypkg-owned link in binDir.
func PruneAll(binDir, activeBinDir string) (pruned []string, err error) {
	return linkfarm.PruneAll(binDir, activeBinDir)
}
