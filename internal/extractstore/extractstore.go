// Package extractstore owns the extracted-package store under
// <stateHome>/pkg-extract. Extract dirs are content-addressed
// (<name>-<version>+<hash16>): a same-version republish is a DIFFERENT
// artifact and lands in a different dir, so the tree an existing
// generation's symlinks resolve through is never rewritten. Sweep removes
// dirs no retained generation references (including crashed ".extract-*"
// temp dirs left by an interrupted extraction).
package extractstore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultMinAge is the grace window sweeps use to defend against the
// unlocked-extraction race: extraction happens before the runner takes
// apply.lock, so a young dir (or in-flight ".extract-*" temp) may belong to a
// concurrent apply whose generation has not committed yet — it looks
// unreferenced to a sweep even though a generation is about to depend on it.
// An hour comfortably exceeds any realistic extract-to-commit gap. Reuse
// refreshes the dir mtime (see planner.ensureExtracted), so both fresh
// extraction and reuse count as recent activity under this window.
const DefaultMinAge = time.Hour

// Root is the extract store's directory under one scope's state home.
func Root(stateHome string) string {
	return filepath.Join(stateHome, "pkg-extract")
}

// DirName is the content-addressed basename for one artifact. contentHash is
// the "blake3:<hex>" form recorded in index and manifest entries; the first
// 16 hex chars (64 bits) key the dir — collision within one name-version is
// not a realistic concern, and the full hash is still enforced end-to-end by
// artifact verification before extraction.
func DirName(name, version, contentHash string) string {
	h := strings.TrimPrefix(contentHash, "blake3:")
	if len(h) > 16 {
		h = h[:16]
	}
	return fmt.Sprintf("%s-%s+%s", name, version, h)
}

// LegacyDirName is the pre-content-addressed layout. Generations committed
// by older binaries recorded absolute symlink targets under this name, so
// sweeps keep it alive while any retained manifest references name-version.
func LegacyDirName(name, version string) string {
	return name + "-" + version
}

// Dir is the absolute content-addressed extract dir for one artifact.
func Dir(stateHome, name, version, contentHash string) string {
	return filepath.Join(Root(stateHome), DirName(name, version, contentHash))
}

// Sweep removes every entry under Root(stateHome) whose basename is not in
// keep AND whose mtime is older than minAge, and returns the removed
// basenames in directory (sorted) order — never nil, so callers can report
// them as a JSON array. The age gate keeps a fresh extraction from an
// in-flight apply alive (see DefaultMinAge); an entry whose mtime cannot be
// read is skipped (fail-safe: never delete what cannot be proven old). A
// missing root means nothing was ever extracted. Removal failures are joined
// and reported after the full pass so one bad dir does not shadow the rest of
// the sweep.
func Sweep(stateHome string, keep map[string]bool, minAge time.Duration) ([]string, error) {
	removed := []string{}
	entries, err := os.ReadDir(Root(stateHome))
	if errors.Is(err, fs.ErrNotExist) {
		return removed, nil
	}
	if err != nil {
		return removed, err
	}
	cutoff := time.Now().Add(-minAge)
	var errs []error
	for _, e := range entries {
		if keep[e.Name()] {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(Root(stateHome), e.Name())); err != nil {
			errs = append(errs, err)
			continue
		}
		removed = append(removed, e.Name())
	}
	return removed, errors.Join(errs...)
}
