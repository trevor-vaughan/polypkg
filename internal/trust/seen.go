package trust

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Seen records the highest trust- and index-document serials observed for a
// source, persisted so a later run can refuse a rolled-back document.
type Seen struct {
	TrustSerial uint64 `json:"trust_serial"`
	IndexSerial uint64 `json:"index_serial"`
	// Packages maps package name -> highest version ever OFFERED by this
	// source's verified index (D15). Entries persist even when a package
	// disappears from the index, so vanish-then-reappear-older still refuses.
	Packages map[string]string `json:"packages,omitempty"`
}

// seenPath is the per-source state file. filepath.Base on the source name keeps
// a stray separator from escaping the trust state directory.
func seenPath(stateHome, source string) string {
	return filepath.Join(stateHome, "trust", filepath.Base(source)+".json")
}

// LoadSeen reads the persisted serials for source. A missing file is the
// trust-on-first-use baseline and returns a zero Seen with no error.
func LoadSeen(stateHome, source string) (Seen, error) {
	var s Seen
	data, err := os.ReadFile(seenPath(stateHome, source))
	if err != nil {
		if os.IsNotExist(err) {
			return Seen{}, nil
		}
		return Seen{}, fmt.Errorf("read trust state: %w", err)
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return Seen{}, fmt.Errorf("parse trust state: %w", err)
	}
	return s, nil
}

// StoreSeen atomically persists the serials for source.
func StoreSeen(stateHome, source string, s Seen) error {
	dir := filepath.Join(stateHome, "trust")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir trust state: %w", err)
	}
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal trust state: %w", err)
	}
	final := seenPath(stateHome, source)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write trust state tmp: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("rename trust state: %w", err)
	}
	return nil
}
