// Package profileedit performs comment-preserving edits on profile files.
// It is the write path for the imperative actions (install/remove/upgrade):
// the profile stays the single source of truth; commands edit it in place.
//
// # Canonical reformatting
//
// Edits route the profile through yaml.v3's node decoder and encoder. The
// encoder normalizes a profile to a canonical form the first time it is
// edited. This is documented, intended behavior — not a bug — because
// comments and meaning are preserved. The only normalization is whitespace:
// runs of spaces before an inline comment collapse to a single space (so
// `user:                # note` becomes `user: # note`). Comment text,
// comment placement (above-key and inline), block scalars, quoting style,
// and entry ordering are all retained. A spike validated this against the
// README example, the install-hello fixture, and a synthetic case with
// above-key comments, inline comments, a `|` block scalar, single- and
// double-quoted strings, and deep indentation; every diff was whitespace
// normalization only.
//
// Version constraints are always written double-quoted (e.g. `">=1.0.0"`)
// so operator-prefixed constraints round-trip unambiguously as strings.
//
// # Durability
//
// Writes are temp+fsync+rename; the parent directory is not fsynced — after
// a crash the edit may revert whole, never tear. Callers keep the returned
// original bytes for explicit rollback.
//
// Both YAML and JSONC/JSON profiles are supported. YAML edits route through
// the yaml.v3 node API; JSONC edits route through hujson.Patch with an
// RFC 6902 patch document, preserving comments and trailing commas.
package profileedit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Edit is one mutation of the packages section.
type Edit struct {
	Scope   string // "user" or "system"
	Name    string // package name
	Version string // constraint to write; empty means REMOVE the package
}

// NotInProfileError reports a remove of a package the profile doesn't have.
type NotInProfileError struct {
	Name  string
	Scope string
	Known []string // package names present in that scope, sorted
}

func (e *NotInProfileError) Error() string {
	if len(e.Known) == 0 {
		return fmt.Sprintf("package %q is not in scope %q of the profile", e.Name, e.Scope)
	}
	return fmt.Sprintf("package %q is not in scope %q of the profile (present: %s)",
		e.Name, e.Scope, strings.Join(e.Known, ", "))
}

// Apply loads the profile at path, applies edits, re-validates the result
// against the profile schema, and atomically rewrites the file (temp+rename,
// preserving mode), keeping comments and the ordering of untouched entries.
// Returns the original file bytes so callers can restore on later failure.
//
// If path is a symlink, the edit is applied to the symlink's target so the
// symlink is never replaced by a regular file (a common setup is
// ~/.config/... -> ~/dotfiles/...).
func Apply(path string, edits []Edit) (original []byte, err error) {
	path = filepath.Clean(path)

	original, err = os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}

	// Resolve any symlink so the temp file lands next to the real file and
	// the rename replaces the target, leaving the symlink intact.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("resolve profile path: %w", err)
	}

	var out []byte
	if isYAMLPath(path) {
		out, err = applyEdits(original, resolved, edits)
	} else {
		out, err = applyEditsJSONC(original, resolved, edits)
	}
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("stat profile: %w", err)
	}

	if err := atomicWrite(resolved, out, info.Mode().Perm()); err != nil {
		return nil, err
	}
	return original, nil
}

// Restore writes original back to path atomically (failure rollback).
//
// Restore unconditionally overwrites the file; callers must hold the
// profile/apply lock for the Apply→Restore window (a concurrent edit in that
// window is discarded).
//
// If path is a symlink, Restore writes through to the symlink's target,
// matching the behaviour of Apply.
func Restore(path string, original []byte) error {
	path = filepath.Clean(path)

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve profile path: %w", err)
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("stat profile: %w", err)
	}
	return atomicWrite(resolved, original, info.Mode().Perm())
}

// isYAMLPath reports whether path uses a YAML extension, mirroring how
// internal/schema dispatches on extension (.yaml/.yml/"" -> YAML).
func isYAMLPath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml", "":
		return true
	default:
		return false
	}
}

// atomicWrite writes data to a temp file in the same directory as path and
// renames it over path, so a crash mid-write never leaves a truncated
// profile. The temp file is created with mode, matching the original.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".profileedit-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before the rename.
	defer func() {
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return errors.Join(fmt.Errorf("write temp file: %w", err), tmp.Close())
	}
	if err := tmp.Chmod(mode); err != nil {
		return errors.Join(fmt.Errorf("chmod temp file: %w", err), tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync temp file: %w", err), tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// ensure NotInProfileError satisfies the error interface at compile time.
var _ error = (*NotInProfileError)(nil)
