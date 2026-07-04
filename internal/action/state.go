package action

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// State ensures a persistent state directory exists for the package and links
// the active tree to it. The stable directory lives at
// Scope.StateRoot/<pkg>/<rel> — outside the swapped generation tree — so its
// contents survive applies, swaps, generation GC, and rollback; only
// `polypkg purge` deletes it. The action never reads, hashes, or heals state
// contents: it guarantees only that the directory exists and that the
// active-tree symlink points at it. It is never drift-checked.
func State(inv Invocation, scope Scope) (Result, error) {
	path, ok := inv.Params["path"].(string)
	if !ok || path == "" {
		return Result{}, fmt.Errorf("state: missing required param 'path'")
	}
	if !scope.Allows(path) {
		return Result{}, fmt.Errorf("state: %q is outside the package scope", path)
	}
	if scope.StateRoot == "" {
		return Result{}, fmt.Errorf("state: no state root configured")
	}
	rel, ok := relWithin(filepath.Join(scope.ActiveRoot, scope.PackageName), path)
	if !ok {
		return Result{}, fmt.Errorf("state: %q is outside the package scope", path)
	}

	// Create the stable dir (if absent) through a StateRoot-confined root so a
	// planted symlink cannot redirect creation; existing contents are untouched.
	if err := os.MkdirAll(scope.StateRoot, 0o700); err != nil {
		return Result{}, fmt.Errorf("state: create state root: %w", err)
	}
	stateRoot, err := os.OpenRoot(scope.StateRoot)
	if err != nil {
		return Result{}, fmt.Errorf("state: open state root: %w", err)
	}
	defer func() { _ = stateRoot.Close() }()
	relStable := filepath.Join(scope.PackageName, rel)
	if err := stateRoot.MkdirAll(relStable, 0o700); err != nil {
		return Result{}, fmt.Errorf("state: create state dir: %w", err)
	}
	stableAbs := filepath.Join(scope.StateRoot, relStable)

	// Place the active-tree symlink -> stable dir (idempotent).
	destRoot, relDest, err := scope.openScope(path)
	if err != nil {
		return Result{}, fmt.Errorf("state: %w", err)
	}
	defer func() { _ = destRoot.Close() }()
	if parent := filepath.Dir(relDest); parent != "." {
		// Active-tree intermediate dirs sit on the system-scope traversal chain,
		// so they take the scope dir mode (like install/symlink). The StateRoot
		// stable dir above stays 0o700 (private; its multi-user readability is a
		// deferred follow-up).
		if err := destRoot.MkdirAll(parent, scope.dirPerm()); err != nil {
			return Result{}, fmt.Errorf("state: create parent dirs for %q: %w", path, err)
		}
	}
	_ = destRoot.Remove(relDest)
	if err := destRoot.Symlink(stableAbs, relDest); err != nil {
		return Result{}, fmt.Errorf("state: symlink %q -> %q: %w", path, stableAbs, err)
	}

	return Result{
		Action:      inv.Action,
		Path:        path,
		Outcome:     "ok",
		Expected:    schema.Expected{FileType: "state", Target: stableAbs},
		DriftPolicy: "state",
	}, nil
}
