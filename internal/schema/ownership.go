package schema

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"
)

//go:embed jsonschema/ownership-v1.json
var ownershipSchemaV1 []byte

// Ownership is the per-generation path-ownership index used by drift and
// file-conflict detection. It is unsigned local state derived at apply time and
// persisted as ownership.json in the generation record.
type Ownership struct {
	Schema  string           `json:"schema"`
	Scope   string           `json:"scope"`
	Entries []OwnershipEntry `json:"entries"`
}

// OwnershipEntry records one drift-relevant action invocation: which package owns
// a path, the action that produced it, the state it should be in, the drift policy
// to apply, and stat() info for incremental re-hashing.
type OwnershipEntry struct {
	Path        string   `json:"path"`
	Package     string   `json:"package"`
	Version     string   `json:"version"`
	Action      string   `json:"action"`
	Expected    Expected `json:"expected"`
	DriftPolicy string   `json:"drift_policy"`
	Stat        StatInfo `json:"stat"`
}

// Expected is the per-action expected state. Different actions populate different
// subsets: install sets FileType+ContentHash, symlink sets FileType+Target,
// dir sets FileType+Mode, perms sets Mode.
type Expected struct {
	FileType    string `json:"file_type,omitempty"`
	ContentHash string `json:"content_hash,omitempty"`
	SourceHash  string `json:"source_hash,omitempty"`
	Target      string `json:"target,omitempty"`
	Mode        string `json:"mode,omitempty"`
	// Priority is the alternatives action's provider priority (higher wins; ties
	// broken by package name). It is required at the alternatives action boundary,
	// so an ownership entry always has an explicit value. omitempty omits a 0
	// priority on marshal, but it round-trips back to 0 on read and arbitration
	// compares plain ints, so 0 is a valid lowest-tier priority and negative
	// values order correctly below it. Unused (zero) by all non-alternatives actions.
	Priority int `json:"priority,omitempty"`
	// Master is the alternatives master name a follower (slave) link belongs
	// to. Set only on alternatives follower ownership entries; empty on
	// primaries and every other action. Arbitration attaches a follower to its
	// master's winning package (internal/alternatives).
	Master string `json:"master,omitempty"`
}

// StatInfo is the lstat data recorded for a managed path so drift detection can
// skip re-hashing when stat is unchanged (apply-semantics §6.4).
type StatInfo struct {
	Size    int64  `json:"size"`
	MtimeNs int64  `json:"mtime_ns"`
	Inode   uint64 `json:"inode"`
}

// StatInfoFrom extracts the ownership StatInfo from an os.FileInfo. Inode comes
// from the Unix stat structure; polypkg is *NIX-only. Callers that need to
// compare a captured StatInfo against a live one must use this constructor so
// the size/mtime/inode triple matches what apply-time capture recorded.
func StatInfoFrom(info os.FileInfo) StatInfo {
	si := StatInfo{Size: info.Size(), MtimeNs: info.ModTime().UnixNano()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		si.Inode = st.Ino
	}
	return si
}

// ParseOwnership reads a JSON ownership index from r, validates it against the
// v1 JSON Schema, and returns the typed representation with a non-nil Entries.
func ParseOwnership(r io.Reader) (*Ownership, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read ownership: %w", err)
	}
	if err := validateAgainstSchema(data, ownershipSchemaV1, "ownership-v1.json"); err != nil {
		return nil, err
	}
	var o Ownership
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("unmarshal ownership: %w", err)
	}
	if o.Entries == nil {
		o.Entries = []OwnershipEntry{}
	}
	return &o, nil
}
