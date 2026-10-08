package action

import (
	"fmt"
	"os"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// Perms implements the `perms` action: set the file mode of a path within the
// package's scope. Only the `mode` parameter is supported; `owner` and `group`
// are rejected rather than silently ignored, so an author is never misled into
// believing ownership was applied.
func Perms(inv Invocation, scope Scope) (Result, error) {
	path, _ := inv.Params["path"].(string)
	if path == "" {
		return Result{Action: "perms", Outcome: "error"}, fmt.Errorf("perms: path required")
	}
	if owner, ok := inv.Params["owner"].(string); ok && owner != "" {
		return Result{Action: "perms", Path: path, Outcome: "error"},
			fmt.Errorf("perms: setting an owner is not supported; only mode can be set")
	}
	if group, ok := inv.Params["group"].(string); ok && group != "" {
		return Result{Action: "perms", Path: path, Outcome: "error"},
			fmt.Errorf("perms: setting a group is not supported; only mode can be set")
	}
	modeStr, _ := inv.Params["mode"].(string)
	var mode os.FileMode
	if modeStr != "" {
		m, err := parseMode(modeStr)
		if err != nil {
			return Result{Action: "perms", Path: path, Outcome: "error"},
				fmt.Errorf("perms: parse mode: %w", err)
		}
		if err := checkModeBits(m); err != nil {
			return Result{Action: "perms", Path: path, Outcome: "error"},
				fmt.Errorf("perms: refusing mode %q for %s: %w", modeStr, path, err)
		}
		mode = m
	}
	root, rel, err := scope.openScope(path)
	if err != nil {
		return Result{Action: "perms", Path: path, Outcome: "error"}, fmt.Errorf("perms: %w", err)
	}
	defer func() { _ = root.Close() }()
	if _, err := root.Stat(rel); err != nil {
		return Result{Action: "perms", Path: path, Outcome: "error"},
			fmt.Errorf("perms: stat: %w", err)
	}
	if modeStr != "" {
		if err := root.Chmod(rel, mode); err != nil {
			return Result{Action: "perms", Path: path, Outcome: "error"},
				fmt.Errorf("perms: chmod: %w", err)
		}
	}
	info, err := root.Lstat(rel)
	if err != nil {
		return Result{Action: "perms", Path: path, Outcome: "error"},
			fmt.Errorf("perms: capture stat: %w", err)
	}
	return Result{
		Action:  "perms",
		Path:    path,
		Outcome: "ok",
		// Planner mirrors this stored form via CanonicalMode — keep in sync.
		Expected: schema.Expected{Mode: fmt.Sprintf("%#o", info.Mode().Perm())},
		Stat:     schema.StatInfoFrom(info),
	}, nil
}
