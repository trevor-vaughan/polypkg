package action

import (
	"fmt"
	"path/filepath"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// Symlink implements the `symlink` action: create a symlink whose dest path is
// within the package's scope. The src (link target) may be any path — a symlink
// relocates neither content nor permissions, so an arbitrary target is not an
// escalation. The link's placement, however, is confined to the scope.
func Symlink(inv Invocation, scope Scope) (Result, error) {
	src, _ := inv.Params["src"].(string)
	dest, _ := inv.Params["dest"].(string)
	if src == "" || dest == "" {
		return Result{Action: "symlink", Outcome: "error"},
			fmt.Errorf("symlink: src and dest are required")
	}
	root, rel, err := scope.openScope(dest)
	if err != nil {
		return Result{Action: "symlink", Path: dest, Outcome: "error"}, fmt.Errorf("symlink: %w", err)
	}
	defer func() { _ = root.Close() }()
	if parent := filepath.Dir(rel); parent != "." {
		if err := root.MkdirAll(parent, scope.dirPerm()); err != nil {
			return Result{Action: "symlink", Path: dest, Outcome: "error"},
				fmt.Errorf("symlink: mkdir parent: %w", err)
		}
	}
	_ = root.Remove(rel)
	if err := root.Symlink(src, rel); err != nil {
		return Result{Action: "symlink", Path: dest, Outcome: "error"},
			fmt.Errorf("symlink: %w", err)
	}
	stat, err := capturedStat(root, rel)
	if err != nil {
		return Result{Action: "symlink", Path: dest, Outcome: "error"},
			fmt.Errorf("symlink: stat: %w", err)
	}
	return Result{
		Action:  "symlink",
		Path:    dest,
		Outcome: "ok",
		// src is the link target verbatim; when it interpolates $ACTIVE it is
		// stored fully expanded. Planner mirrors this in projectExpected
		// ("symlink" case), expanding $ACTIVE against the diff baseline's active
		// root so a converged plan compares equal — keep in sync.
		Expected: schema.Expected{FileType: "symlink", Target: src},
		Stat:     stat,
	}, nil
}
