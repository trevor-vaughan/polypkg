package action

import (
	"fmt"
	"os"
	"strconv"
	"strings"

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
		if err := checkModeBits(m); err != nil {
			return Result{Action: "dir", Path: path, Outcome: "error"},
				fmt.Errorf("dir: refusing mode %q for %s: %w", modeStr, path, err)
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

// AllowedModeBits is every bit a manifest mode (the dir and perms actions'
// mode param) may set: owner rwx, group and other r-x. Group- or other-write
// would let another local user replace a file that root placed and that
// /usr/local/bin links to; setuid and setgid would make a package file a
// privilege boundary; sticky has no use on a package-owned path. chmod ignores
// the umask, so nothing downstream masks these. The rule does not depend on
// scope, which lets pkg lint (which cannot know the scope) flag exactly what
// apply refuses.
const AllowedModeBits = os.FileMode(0o755)

// modeBitNames names each bit outside AllowedModeBits that a mode literal of
// at most 0o7777 can set, in the order checkModeBits lists them.
var modeBitNames = []struct {
	bit  os.FileMode
	name string
}{
	{0o4000, "setuid"},
	{0o2000, "setgid"},
	{0o1000, "sticky"},
	{0o020, "group-write"},
	{0o002, "other-write"},
}

// checkModeBits refuses a mode from parseMode that sets any bit outside
// AllowedModeBits, naming each offending bit. parseMode returns the raw octal
// value, so 0o4000 here is the literal setuid bit. A value above 0o7777 is
// refused too: os.FileMode reads those bits as type flags (0o40000000 is
// os.ModeSetuid), and chmod would honour them.
func checkModeBits(mode os.FileMode) error {
	extra := mode &^ AllowedModeBits
	if extra == 0 {
		return nil
	}
	var names []string
	for _, b := range modeBitNames {
		if extra&b.bit != 0 {
			names = append(names, b.name)
			extra &^= b.bit
		}
	}
	if extra != 0 {
		names = append(names, "bits outside 0o7777")
	}
	return fmt.Errorf("sets %s; a mode may use only the bits in %#o", strings.Join(names, ", "), AllowedModeBits)
}

// CheckMode parses a manifest mode literal and applies the rule the dir and
// perms actions enforce at apply time (see AllowedModeBits), so pkg lint
// reports exactly the modes apply would refuse, in the same words.
func CheckMode(s string) error {
	mode, err := parseMode(s)
	if err != nil {
		return err
	}
	return checkModeBits(mode)
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
