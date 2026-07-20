package schema

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
)

//go:embed jsonschema/trust-bundle-v1.json
var trustBundleSchemaV1 []byte

// BuilderKey is one external build-signer key the publisher vouches for in a
// polypkg.trust-bundle/v1 document. Keys are append-only and time-windowed:
// retiring a key sets ValidUntil, entries are never removed (historical pool
// blobs still need their signing key to verify). A carried DSSE signature is
// accepted only if its key was within [ValidFrom, ValidUntil] at the
// attestation's build timestamp — enforced by Bundle.BuilderKeyAt, not here.
type BuilderKey struct {
	KeyID        string `json:"key_id"`
	PublicKey    string `json:"public_key"`              // base64, algo-specific
	Algo         string `json:"algo"`                    // "ed25519" (v1)
	ValidFrom    string `json:"valid_from"`              // RFC3339
	ValidUntil   string `json:"valid_until,omitempty"`   // RFC3339; absent = open-ended
	SupersededBy string `json:"superseded_by,omitempty"` // key_id of the replacement (audit only)
}

// SigstoreRoot is a time-windowed set of sigstore trust anchors (Fulcio CA
// chain, Rekor keys, optional CT-log keys). Carried verbatim in v1; consumed
// by the sigstore verifier in a later phase.
type SigstoreRoot struct {
	ValidFrom  string   `yaml:"valid_from"            json:"valid_from"`            // RFC3339
	ValidUntil string   `yaml:"valid_until,omitempty" json:"valid_until,omitempty"` // RFC3339; absent = open-ended
	FulcioCA   []string `yaml:"fulcio_ca"             json:"fulcio_ca"`             // base64 DER certs (root + intermediates)
	RekorKeys  []string `yaml:"rekor_keys"            json:"rekor_keys"`            // base64 public keys
	CTLogKeys  []string `yaml:"ctlog_keys,omitempty"  json:"ctlog_keys,omitempty"`  // base64 public keys
}

// TrustBundle is a source's signed, freshness-bounded statement of the builder
// keys and sigstore roots its publisher vouches for (polypkg.trust-bundle/v1).
// It is separate from the polypkg.trust/v2 role model: builder keys are not
// signing roles. Callers MUST verify its signature before trusting parsed
// contents (see trust.LoadBundle).
type TrustBundle struct {
	Schema        string         `json:"schema"`
	Source        string         `json:"source"`
	Serial        uint64         `json:"serial"`
	IssuedAt      string         `json:"issued_at,omitempty"`
	Expires       string         `json:"expires"` // RFC3339; consumer rejects stale (D13)
	BuilderKeys   []BuilderKey   `json:"builder_keys,omitempty"`
	SigstoreRoots []SigstoreRoot `json:"sigstore_roots,omitempty"`
}

// ParseTrustBundle reads a JSON trust bundle, rejects unknown fields, and
// validates it against the embedded v1 JSON Schema.
func ParseTrustBundle(r io.Reader) (*TrustBundle, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read trust bundle: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var b TrustBundle
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("decode trust bundle: %w", err)
	}
	if err := validateAgainstSchema(data, trustBundleSchemaV1, "trust-bundle-v1.json"); err != nil {
		return nil, err
	}
	// A builder key id selects a key both for signature verification
	// (Bundle.BuilderKey, first match) and for the build-time window gate
	// (Bundle.BuilderKeyAt, first in-window match). If two entries shared an id
	// those selectors could resolve to different keys, letting an out-of-window
	// signing key pass the gate via a sibling entry. Rotation supersedes with a
	// NEW id (superseded_by), never reuses one, so a duplicate id is a malformed
	// bundle — reject it (fail closed).
	seen := make(map[string]struct{}, len(b.BuilderKeys))
	for _, k := range b.BuilderKeys {
		if _, dup := seen[k.KeyID]; dup {
			return nil, fmt.Errorf("trust bundle has duplicate builder key_id %q", k.KeyID)
		}
		seen[k.KeyID] = struct{}{}
	}
	return &b, nil
}
