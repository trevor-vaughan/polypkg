package trust

import (
	"encoding/json"
	"fmt"
	"maps"
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
	// PackagesByPlatform maps host platform -> package name -> highest version
	// this source's verified index ever OFFERED to that host. Entries persist
	// even when a package disappears from the index, so
	// vanish-then-reappear-older still refuses. Keyed by host because a state
	// home can be shared by machines of different platforms, and one platform's
	// newer build must not refuse another platform's older one as a downgrade.
	// Read it through HighWater.
	PackagesByPlatform map[string]map[string]string `json:"packages_by_platform,omitempty"`
	// Packages is the un-keyed high-water map written before marks were kept
	// per platform. It is only read, by HighWater, to seed a host that has no
	// marks yet; writers leave it empty so it drops out of the file. An older
	// polypkg that rewrites the file knows only this field and drops
	// PackagesByPlatform, losing other hosts' marks; accepted while polypkg is
	// pre-release. Its own host's marks come back through this adoption.
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
	// RevokedAttestations is the set of attestation content-hashes this source's
	// revocation list revoked, as of the last fetch. Informational, offline-readable
	// state for `status`; NEVER consulted by the anti-rollback floors. Empty/absent
	// when the last fetch saw no revocation list or no revoked attestations —
	// StoreSeen overwrites the whole file, so a later fetch with none clears it.
	RevokedAttestations []string `json:"revoked_attestations,omitempty"`
	// RevocationExpires is the RFC3339 expires of the revocation list seen at the
	// last fetch of this source. Informational, offline-readable state for
	// `status`; NEVER consulted by the anti-rollback serial floors. Empty/absent
	// when the last fetch saw no revocation list — StoreSeen overwrites the whole
	// file, so a later fetch with none clears it.
	RevocationExpires string `json:"revocation_expires,omitempty"`
}

// HighWater returns a copy of host's package high-water marks, never nil.
// When host has no marks yet, a legacy un-keyed Packages map is adopted as
// host's, so upgrading from that format loses no rollback protection.
func (s Seen) HighWater(host string) map[string]string {
	src, ok := s.PackagesByPlatform[host]
	if !ok {
		src = s.Packages
	}
	out := maps.Clone(src)
	if out == nil {
		out = map[string]string{}
	}
	return out
}

// RollbackError is a signed document served at a serial below the persisted
// anti-rollback floor. Its text is the one the loaders have always returned;
// the type lets a caller tell a floor refusal apart from any other failure.
type RollbackError struct {
	Document string // "trust document", "index", "trust bundle", "revocation list"
	Serial   uint64 // the serial the document carries
	LastSeen uint64 // the floor it fell below
}

func (e *RollbackError) Error() string {
	return fmt.Sprintf("%s rollback: serial %d is below last-seen %d", e.Document, e.Serial, e.LastSeen)
}

// SeenPath is the per-source state file. filepath.Base on the source name keeps
// a stray separator from escaping the trust state directory.
func SeenPath(stateHome, source string) string {
	return filepath.Join(stateHome, "trust", filepath.Base(source)+".json")
}

// LoadSeen reads the persisted serials for source. A missing file is the
// trust-on-first-use baseline and returns a zero Seen with no error.
func LoadSeen(stateHome, source string) (Seen, error) {
	var s Seen
	data, err := os.ReadFile(SeenPath(stateHome, source))
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
	final := SeenPath(stateHome, source)
	// A unique temp name per call, so concurrent writers of one source never
	// share (and rename) each other's half-written file. CreateTemp opens it
	// 0600, the same mode the record always had.
	tmp, err := os.CreateTemp(dir, filepath.Base(final)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create trust state tmp: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write trust state tmp: %w", err)
	}
	// Flush the bytes before the rename publishes them: otherwise a crash can
	// leave a renamed but empty record, which LoadSeen then refuses to parse.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync trust state tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close trust state tmp: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("rename trust state: %w", err)
	}
	committed = true
	// Make the rename itself durable.
	d, err := os.Open(dir) //nolint:gosec // G304: the trust state dir created above
	if err != nil {
		return fmt.Errorf("open trust state dir: %w", err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("sync trust state dir: %w", err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("close trust state dir: %w", err)
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
	if err := os.Remove(SeenPath(stateHome, source)); err != nil && !os.IsNotExist(err) {
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
