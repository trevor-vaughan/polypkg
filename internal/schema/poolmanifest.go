package schema

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
)

//go:embed jsonschema/pool-manifest-v1.json
var poolManifestSchemaV1 []byte

// Pool-entry kinds. Every file carried in an export bundle is classified by one
// of these; the completeness manifest (a signed bill of materials) lists every
// bundled file except itself and its own detached signature.
const (
	PoolKindIndex             = "index"
	PoolKindIndexSig          = "index-sig"
	PoolKindTrust             = "trust"
	PoolKindTrustSig          = "trust-sig"
	PoolKindTrustBundle       = "trust-bundle"
	PoolKindTrustBundleSig    = "trust-bundle-sig"
	PoolKindRevocationList    = "revocation-list"
	PoolKindRevocationListSig = "revocation-list-sig"
	PoolKindTrustRoot         = "trust-root"
	PoolKindArtifact          = "artifact"
	PoolKindArtifactSig       = "artifact-sig"
	PoolKindAttestation       = "attestation"
	PoolKindAttestationSig    = "attestation-sig"
)

// PoolEntry is one file in an export bundle: its bundle-relative path, its
// BLAKE3 content hash ("blake3:<hex>"), and its classified kind.
type PoolEntry struct {
	Path        string `json:"path"`
	ContentHash string `json:"content_hash"`
	Kind        string `json:"kind"`
}

// PoolManifest (polypkg.pool-manifest/v1) is the signed completeness manifest —
// a bill of materials — for a `polypkg repo export-bundle` tarball. It is
// signed by the SAME key that signs the repository's index, so it is trusted
// exactly when that index is. Serial and IssuedAt are inherited from the repo's
// trust document and Expires from its index, so a bundle's freshness tracks the
// repo snapshot it mirrors.
type PoolManifest struct {
	Schema   string      `json:"schema"`
	Source   string      `json:"source"`
	Serial   uint64      `json:"serial"`
	IssuedAt string      `json:"issued_at,omitempty"`
	Expires  string      `json:"expires"`
	Entries  []PoolEntry `json:"entries"`
}

// ParsePoolManifest strictly decodes and schema-validates a pool manifest, then
// rejects duplicate entry paths (a manifest defect that would let a bundle carry
// two files claiming the same slot).
func ParsePoolManifest(r io.Reader) (*PoolManifest, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read pool manifest: %w", err)
	}
	if err := checkNotNewer(data, poolManifestSchemaV1); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m PoolManifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode pool manifest: %w", err)
	}
	if err := validateAgainstSchema(data, poolManifestSchemaV1, "pool-manifest-v1.json"); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(m.Entries))
	for _, e := range m.Entries {
		if _, dup := seen[e.Path]; dup {
			return nil, fmt.Errorf("pool manifest has duplicate entry path %q", e.Path)
		}
		seen[e.Path] = struct{}{}
	}
	return &m, nil
}
