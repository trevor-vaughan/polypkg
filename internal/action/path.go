package action

import (
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// pathNameRe is the shared-command-name grammar: a single safe path component
// (no separators, no "."/".."). It compiles the registry's shared namePattern
// so the runtime check and the declarative lint table cannot diverge.
var pathNameRe = regexp.MustCompile(namePattern)

// Path exposes a package's own installed binary on $PATH by creating a symlink
// in the shared bin directory (<ActiveRoot>/bin/<name>) pointing at the
// package's file. The shared link lives outside the package namespace, so two
// packages exposing the same command name produce the same ownership path
// (bin/<name>) — a collision the runner and planner detect (internal/conflict)
// and refuse. The source (link target) is confined to the package's own
// namespace: a package may only expose its own files, never another package's
// or an arbitrary host path. The target need not exist at creation (symlinks
// may dangle); it is recorded as a symlink entry and drift-checked as one.
// Result.Path is the absolute filesystem path (<ActiveRoot>/bin/<name>);
// dispatch relativizes it via filepath.Rel(ActiveRoot, res.Path) to produce
// the bin/<name> ownership path before recording it in the ownership store.
func Path(inv Invocation, scope Scope) (Result, error) {
	name, _ := inv.Params["name"].(string)
	if !pathNameRe.MatchString(name) {
		return Result{Action: "path", Outcome: "error"},
			fmt.Errorf("path: invalid or missing 'name' (must match [a-zA-Z0-9_-]+)")
	}
	source, _ := inv.Params["source"].(string)
	if source == "" {
		return Result{Action: "path", Outcome: "error"}, fmt.Errorf("path: 'source' is required")
	}
	if !scope.Allows(source) {
		return Result{Action: "path", Outcome: "error"},
			fmt.Errorf("path: source %q is outside the package scope", source)
	}
	root, err := scope.openSharedSubtree(SharedBinDir)
	if err != nil {
		return Result{Action: "path", Outcome: "error"}, fmt.Errorf("path: %w", err)
	}
	defer func() { _ = root.Close() }()
	_ = root.Remove(name)
	if err := root.Symlink(source, name); err != nil {
		return Result{Action: "path", Outcome: "error"},
			fmt.Errorf("path: symlink %q: %w", name, err)
	}
	absPath := filepath.Join(scope.ActiveRoot, SharedBinDir, name) // absolute; dispatch relativizes to the bin/<name> ownership entry
	stat, err := capturedStat(root, name)
	if err != nil {
		return Result{Action: "path", Path: absPath, Outcome: "error"},
			fmt.Errorf("path: stat: %w", err)
	}
	return Result{
		Action:  "path",
		Path:    absPath,
		Outcome: "ok",
		// source is the $ACTIVE-expanded absolute link target. Planner mirrors
		// this in projectExpected ("path" case), expanding $ACTIVE against the
		// diff baseline's active root so a converged plan compares equal — keep
		// in sync.
		Expected: schema.Expected{FileType: "symlink", Target: source},
		Stat:     stat,
	}, nil
}
