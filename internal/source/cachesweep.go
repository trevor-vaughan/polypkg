package source

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// cacheMetadataFiles are the signed metadata documents FetchIndex,
// FetchTrustDoc, and fetchOptionalMeta cache beside a source's artifacts.
// Every fetch overwrites them, so they never accumulate; sweeps leave them.
var cacheMetadataFiles = map[string]bool{
	"index.json":        true,
	"trust.json":        true,
	"trust-bundle.json": true,
	"revocations.json":  true,
}

// CacheRoot is the directory under one scope's state home that holds a
// NativeBackend cache per source (<CacheRoot>/<source>/).
func CacheRoot(stateHome string) string {
	return filepath.Join(stateHome, "cache")
}

// SweepArtifactCache removes cached artifacts no retained generation
// references from every per-source cache under CacheRoot(stateHome), and
// returns them as "<source>/<file>" in sorted order — never nil, so callers
// can report them as a JSON array.
//
// keep holds artifact base names: Fetch keys the cache by filepath.Base of
// the index-supplied artifact path. Signed metadata documents and anything
// that is not a regular file are never removed. A file younger than minAge is
// kept: the planner fetches before the runner takes apply.lock, so a young
// unreferenced artifact may belong to an apply whose generation has not
// committed yet (deleting it would only cost that apply a re-download, since
// Fetch reads the whole file into memory and refetches on a miss, but there is
// no reason to). A file whose mtime cannot be read is skipped. A missing root
// means nothing was ever cached. Removal failures are joined and reported
// after the full pass.
func SweepArtifactCache(stateHome string, keep map[string]bool, minAge time.Duration) ([]string, error) {
	removed := []string{}
	root := CacheRoot(stateHome)
	sources, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return removed, nil
	}
	if err != nil {
		return removed, err
	}
	cutoff := time.Now().Add(-minAge)
	var errs []error
	for _, src := range sources {
		if !src.IsDir() {
			continue
		}
		dir := filepath.Join(root, src.Name())
		entries, err := os.ReadDir(dir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if keep[name] || cacheMetadataFiles[name] || !e.Type().IsRegular() {
				continue
			}
			info, err := e.Info()
			if err != nil || info.ModTime().After(cutoff) {
				continue
			}
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				errs = append(errs, err)
				continue
			}
			removed = append(removed, src.Name()+"/"+name)
		}
	}
	return removed, errors.Join(errs...)
}
