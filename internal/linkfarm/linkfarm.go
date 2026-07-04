// Package linkfarm reconciles a directory of symlinks against a wanted set,
// owning only links whose target points directly into a given owned directory.
// It is the conflict-safe primitive shared by the ~/.local/bin bridge and the
// shell-completion installer: it creates or repoints "our" links, prunes our
// links no longer wanted, and never touches a foreign entry.
package linkfarm

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Conflict is a wanted link whose slot is occupied by a foreign entry.
type Conflict struct {
	Name     string // the link name
	Existing string // the foreign symlink's target, or "file"/"dir"
}

// Result reports what a Reconcile changed, for operator-facing summaries.
type Result struct {
	Linked  []string
	Pruned  []string
	Skipped []Conflict
}

// IsComponent reports whether name is a single safe path component (no
// separators, not ""/"."/".."). Callers filter to components defensively.
func IsComponent(name string) bool {
	return name != "" && name != "." && name != ".." &&
		!strings.ContainsAny(name, `/\`) && name == filepath.Base(name)
}

// ownedTarget reports whether a symlink target points directly into ownedDir —
// i.e. it is a link this package created. Ownership is defined by the target
// alone, so a user who hand-creates such a link takes on its management.
func ownedTarget(target, ownedDir string) bool {
	return filepath.Dir(target) == filepath.Clean(ownedDir)
}

// Reconcile makes dir contain exactly the symlinks in want (name -> target),
// owning any symlink whose target sits directly in ownedDir, repointing stale
// ours-links, pruning ours-links not in want, and never overwriting or removing
// a foreign entry (those collide into Skipped). All operations are confined to
// dir via os.OpenRoot. dir is created (0o750) if absent; an existing dir's
// permissions are left as-is.
//
// The Lstat->Remove/Symlink sequence has an accepted TOCTOU window: a process
// with write access to dir could swap an entry between check and mutation. dir
// is the user's own directory, so any such process already runs as the user.
func Reconcile(dir, ownedDir string, want map[string]string) (Result, error) {
	var res Result
	for name := range want {
		if !IsComponent(name) {
			return res, fmt.Errorf("linkfarm: invalid link name %q", name)
		}
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return res, fmt.Errorf("create dir: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return res, fmt.Errorf("open dir: %w", err)
	}
	defer func() { _ = root.Close() }()

	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		expected := want[name]
		fi, lerr := root.Lstat(name)
		if lerr != nil {
			if !os.IsNotExist(lerr) {
				return res, fmt.Errorf("lstat %q: %w", name, lerr)
			}
			if err := root.Symlink(expected, name); err != nil {
				return res, fmt.Errorf("link %q: %w", name, err)
			}
			res.Linked = append(res.Linked, name)
			continue
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			kind := "file"
			if fi.IsDir() {
				kind = "dir"
			}
			res.Skipped = append(res.Skipped, Conflict{Name: name, Existing: kind})
			continue
		}
		tgt, rerr := root.Readlink(name)
		if rerr != nil {
			return res, fmt.Errorf("readlink %q: %w", name, rerr)
		}
		if tgt == expected {
			continue
		}
		if ownedTarget(tgt, ownedDir) {
			if err := root.Remove(name); err != nil {
				return res, fmt.Errorf("repoint %q: %w", name, err)
			}
			if err := root.Symlink(expected, name); err != nil {
				return res, fmt.Errorf("link %q: %w", name, err)
			}
			res.Linked = append(res.Linked, name)
			continue
		}
		res.Skipped = append(res.Skipped, Conflict{Name: name, Existing: tgt})
	}

	dents, err := os.ReadDir(dir)
	if err != nil {
		return res, fmt.Errorf("read dir: %w", err)
	}
	for _, d := range dents {
		if _, ok := want[d.Name()]; ok {
			continue
		}
		if pruned, err := pruneIfOurs(root, d.Name(), ownedDir); err != nil {
			return res, err
		} else if pruned {
			res.Pruned = append(res.Pruned, d.Name())
		}
	}

	sort.Strings(res.Linked)
	sort.Strings(res.Pruned)
	sort.Slice(res.Skipped, func(i, j int) bool { return res.Skipped[i].Name < res.Skipped[j].Name })
	return res, nil
}

// pruneIfOurs removes dir/<name> iff it is a symlink into ownedDir. Returns
// whether it removed the entry. Foreign entries are left untouched.
func pruneIfOurs(root *os.Root, name, ownedDir string) (bool, error) {
	fi, lerr := root.Lstat(name)
	if lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
		return false, nil
	}
	tgt, rerr := root.Readlink(name)
	if rerr != nil {
		return false, nil
	}
	if !ownedTarget(tgt, ownedDir) {
		return false, nil
	}
	if err := root.Remove(name); err != nil {
		return false, fmt.Errorf("prune %q: %w", name, err)
	}
	return true, nil
}

// PruneAll removes every ours-link in dir (symlinks into ownedDir), leaving
// foreign entries untouched. A missing dir is a no-op.
func PruneAll(dir, ownedDir string) (pruned []string, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open dir: %w", err)
	}
	defer func() { _ = root.Close() }()
	dents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}
	for _, d := range dents {
		if ok, err := pruneIfOurs(root, d.Name(), ownedDir); err != nil {
			return pruned, err
		} else if ok {
			pruned = append(pruned, d.Name())
		}
	}
	sort.Strings(pruned)
	return pruned, nil
}
