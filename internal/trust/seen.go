package trust

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SeenGrace is the freshness-grace posture recorded at the last fetch of a
// source: the metadata documents accepted past their expiry under the operator's
// accept_expiry_until, and that deadline. Informational only — it is NOT consulted
// by the anti-rollback serial floors; it exists so the offline `status` command
// can report that the source was last fetched under grace.
type SeenGrace struct {
	AcceptUntil string   `json:"accept_until"`
	Docs        []string `json:"docs"`
}

// DocRevocationList is the SeenGrace.Docs / GracedMetadata label for a source's
// revocation list. Shared because status's grace-acknowledgement match gates an
// exit code — a divergent literal would silently misfire it.
const DocRevocationList = "revocation list"

// Seen records the highest trust- and index-document serials observed for a
// source, persisted so a later run can refuse a rolled-back document.
type Seen struct {
	TrustSerial uint64 `json:"trust_serial"`
	IndexSerial uint64 `json:"index_serial"`
	// BundleSerial and RevocationSerial are the highest serials observed for
	// this source's optional trust bundle and revocation list (2c-0). Missing
	// from an older state file ⇒ 0 ⇒ never-seen (the trust-on-first-use
	// baseline), which is why absence of the doc on the wire is only refused
	// once one of these is above zero.
	BundleSerial     uint64 `json:"bundle_serial,omitempty"`
	RevocationSerial uint64 `json:"revocation_serial,omitempty"`
	// Packages maps package name -> highest version ever OFFERED by this
	// source's verified index (D15). Entries persist even when a package
	// disappears from the index, so vanish-then-reappear-older still refuses.
	Packages map[string]string `json:"packages,omitempty"`
	// Graced records that this source's metadata was accepted under freshness
	// grace at the last fetch. Nil/absent when the last fetch needed no grace —
	// because StoreSeen overwrites the whole file, an ungraced fetch clears it.
	Graced *SeenGrace `json:"graced,omitempty"`
	// RevokedBuilderKeys is the set of builder key IDs this source's revocation
	// list revoked, as of the last fetch. Informational, offline-readable state
	// for `status`; NOT consulted by the anti-rollback floors. Empty/absent when
	// the last fetch saw no revocation list or no revoked keys — StoreSeen
	// overwrites the whole file, so a later fetch with none clears it.
	RevokedBuilderKeys []string `json:"revoked_builder_keys,omitempty"`
	// RevocationExpires is the RFC3339 expires of the revocation list seen at the
	// last fetch of this source. Informational, offline-readable state for
	// `status`; NEVER consulted by the anti-rollback serial floors. Empty/absent
	// when the last fetch saw no revocation list — StoreSeen overwrites the whole
	// file, so a later fetch with none clears it.
	RevocationExpires string `json:"revocation_expires,omitempty"`
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

// ForgetSeen removes the persisted serial floors for source. A missing file is
// not an error: forgetting an already-absent source is a no-op. This is the
// consumer half of the recovery story (spec §10.1): after `source remove`, a
// later re-add of the same name re-pins from a clean trust-on-first-use
// baseline instead of inheriting stale anti-rollback floors that would refuse a
// legitimately re-created repository.
func ForgetSeen(stateHome, source string) error {
	if err := os.Remove(seenPath(stateHome, source)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove trust state: %w", err)
	}
	return nil
}

// ListSeenSources returns the source names with persisted trust state under
// stateHome — the base filenames of <stateHome>/trust/*.json without the
// extension. A missing trust dir yields an empty list and no error. Order is
// unspecified; callers sort.
func ListSeenSources(stateHome string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(stateHome, "trust"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read trust state dir: %w", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		out = append(out, strings.TrimSuffix(name, ".json"))
	}
	return out, nil
}
