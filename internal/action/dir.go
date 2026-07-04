package action

import (
	"fmt"
	"os"
	"strconv"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// DefaultDirMode is the mode a dir action uses when its mode param is absent.
// The planner projection must use the same default.
const DefaultDirMode = os.FileMode(0o755)

// Dir implements the `dir` action: declare ownership of a directory within the
// package's scope, creating it (and parents) and setting its mode.
func Dir(inv Invocation, scope Scope) (Result, error) {
	path, _ := inv.Params["path"].(string)
	if path == "" {
		return Result{Action: "dir", Outcome: "error"}, fmt.Errorf("dir: path required")
	}
	modeStr, _ := inv.Params["mode"].(string)
	mode := DefaultDirMode
	if modeStr != "" {
		m, err := parseMode(modeStr)
		if err != nil {
			return Result{Action: "dir", Path: path, Outcome: "error"},
				fmt.Errorf("dir: parse mode %q: %w", modeStr, err)
		}
		mode = m
	}
	root, rel, err := scope.openScope(path)
	if err != nil {
		return Result{Action: "dir", Path: path, Outcome: "error"}, fmt.Errorf("dir: %w", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirAll(rel, mode); err != nil {
		return Result{Action: "dir", Path: path, Outcome: "error"},
			fmt.Errorf("dir: mkdir: %w", err)
	}
	if err := root.Chmod(rel, mode); err != nil {
		return Result{Action: "dir", Path: path, Outcome: "error"},
			fmt.Errorf("dir: chmod: %w", err)
	}
	stat, err := capturedStat(root, rel)
	if err != nil {
		return Result{Action: "dir", Path: path, Outcome: "error"},
			fmt.Errorf("dir: stat: %w", err)
	}
	// Expected.Mode is the requested mode (the desired state for drift), not a
	// post-chmod lstat; they agree on success and drift fires if they diverge.
	return Result{
		Action:  "dir",
		Path:    path,
		Outcome: "ok",
		// Planner mirrors this stored form via CanonicalMode — keep in sync.
		Expected: schema.Expected{FileType: "dir", Mode: fmt.Sprintf("%#o", mode.Perm())},
		Stat:     stat,
	}, nil
}

func parseMode(s string) (os.FileMode, error) {
	if len(s) > 2 && s[0] == '0' && (s[1] == 'o' || s[1] == 'O') {
		s = s[2:]
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, err
	}
	return os.FileMode(n), nil
}

// CanonicalMode normalizes a manifest mode literal (e.g. "0o755", "0755",
// "755") to the canonical "%#o" form the dir and perms actions record in
// ownership Expected.Mode and that drift compares against. The planner uses
// this so its projected mode matches the runner's stored mode by construction;
// without it a converged system reports false mode drift ("0o755" vs "0755").
func CanonicalMode(s string) (string, error) {
	mode, err := parseMode(s)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%#o", mode.Perm()), nil
}
