package repo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// CacheEntry records the last successful build of one package source.
type CacheEntry struct {
	Fingerprint string `json:"fingerprint"`
	ContentHash string `json:"content_hash"`
	Artifact    string `json:"artifact"`
	Version     string `json:"version"`
	Revision    int    `json:"revision"` // informational rebuild ordinal (D10)
	// Per-entry attestation refs, reused verbatim on cache hits so an unchanged
	// package keeps its published attestation set. Empty when the entry was built
	// with --skip-attestations. A list (not a single ref) so carried external
	// provenance is preserved across rebuilds, not silently stripped.
	Attestations []schema.AttestationRef `json:"attestations,omitempty"`
	Depends      []schema.Relation       `json:"depends,omitempty"`
	Recommends   []schema.Relation       `json:"recommends,omitempty"`
	Suggests     []schema.Relation       `json:"suggests,omitempty"`
	Provides     []schema.Relation       `json:"provides,omitempty"`
	Conflicts    []schema.Relation       `json:"conflicts,omitempty"`
	Obsoletes    []schema.Relation       `json:"obsoletes,omitempty"`
}

// indexEntry renders the cached package state as the index entry to republish on
// a cache hit, so the source and prebuilt reuse paths can't drift on the field set.
func (c CacheEntry) indexEntry() schema.IndexEntry {
	return schema.IndexEntry{
		Version:      c.Version,
		ContentHash:  c.ContentHash,
		Artifact:     c.Artifact,
		Revision:     c.Revision,
		Attestations: c.Attestations,
		Depends:      c.Depends,
		Recommends:   c.Recommends,
		Suggests:     c.Suggests,
		Provides:     c.Provides,
		Conflicts:    c.Conflicts,
		Obsoletes:    c.Obsoletes,
	}
}

// BuildCache makes `repo build` incremental: a package whose source fingerprint
// is unchanged is not re-packed/re-signed. Serial is the publisher's monotonic
// counter, bumped only when published content actually changes. It lives beside
// the key (outside the served output directory).
type BuildCache struct {
	Schema  string                `json:"schema"`
	Serial  uint64                `json:"serial"`
	Entries map[string]CacheEntry `json:"entries"`
	// ValidFor is the validity window (in nanoseconds) that the currently
	// published index.json/trust.json expiry was stamped with. The published
	// documents carry the expiry but not the window that produced it — index.json
	// has no issued_at, and trust.json's is pinned to the epoch for deterministic
	// signatures — so the window is recorded here, next to the serial, and read
	// back by both Build and Inspector.Pending to apply the D13 half-life rule
	// against the real window rather than a guess.
	//
	// Zero means "not recorded": a cache written before this field existed, or a
	// cold one. effectiveWindow resolves that to DefaultValidFor, the window the
	// half-life rule assumed before it was recorded. Adding the field needs no
	// schema bump for that reason — an old cache stays readable and keeps its
	// previous behaviour.
	ValidFor time.Duration `json:"valid_for,omitempty"`
}

// NewBuildCache returns an empty cache.
func NewBuildCache() *BuildCache {
	return &BuildCache{Schema: "polypkg.repo-cache/v3", Entries: map[string]CacheEntry{}}
}

// Get returns the cache entry for a package source path.
func (c *BuildCache) Get(source string) (CacheEntry, bool) { e, ok := c.Entries[source]; return e, ok }

// Put records the cache entry for a package source path.
func (c *BuildCache) Put(source string, e CacheEntry) { c.Entries[source] = e }

// LoadBuildCache reads a cache file. A missing file yields a fresh empty cache
// (a cold or invalidated cache is never an error); a corrupt file is treated as
// cold rather than fatal. Any schema other than the current v3 is also treated
// as cold: a stale v1 entry carries a flat artifact name that would leak into a
// pool-addressed index (D-C8), and a v2 entry carries single-attestation fields
// v3 no longer models. Build floors the serial against the published trust.json,
// so zeroing it here cannot regress a published serial.
func LoadBuildCache(path string) (*BuildCache, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is the build cache alongside the key; user controls key-dir
	if errors.Is(err, fs.ErrNotExist) {
		return NewBuildCache(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read build cache: %w", err)
	}
	var c BuildCache
	if err := json.Unmarshal(raw, &c); err != nil {
		return NewBuildCache(), nil
	}
	if c.Schema != "polypkg.repo-cache/v3" {
		return NewBuildCache(), nil
	}
	if c.Entries == nil {
		c.Entries = map[string]CacheEntry{}
	}
	return &c, nil
}

// Save atomically writes the cache (0600 — it sits next to the secret key).
func (c *BuildCache) Save(path string) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// The default --key-dir is an XDG data path that need not exist yet, and by
	// the time Save runs the repository is already built, signed, and
	// published. Failing here would report failure for completed work. 0700
	// because this directory also holds the encrypted signing key.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create build cache dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write build cache: %w", err)
	}
	return os.Rename(tmp, path)
}

// SourceFingerprint hashes the sorted (relpath, size, mtimeNano) of every file
// under dir. Cheap to compute and changes whenever any source file changes.
func SourceFingerprint(dir string) (string, error) {
	var lines []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(dir, p)
		if relErr != nil {
			return relErr
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		lines = append(lines, filepath.ToSlash(rel)+"\x00"+
			strconv.FormatInt(info.Size(), 10)+"\x00"+
			strconv.FormatInt(info.ModTime().UnixNano(), 10))
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("fingerprint %s: %w", dir, err)
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		_, _ = h.Write([]byte(l))
		_, _ = h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
