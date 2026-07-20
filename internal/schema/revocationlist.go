package schema

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
)

//go:embed jsonschema/revocation-list-v1.json
var revocationListSchemaV1 []byte

// RevocationList is a source's signed, freshness-bounded list of revoked
// builder keys and revoked attestations (polypkg.revocation-list/v1). It is a
// SEPARATE document from the trust bundle (spec §5.1) with its own serial and
// expires, so a revocation ships without a full bundle republish. Callers MUST
// verify its signature before trusting parsed contents (see
// trust.LoadRevocationList).
type RevocationList struct {
	Schema              string   `json:"schema"`
	Source              string   `json:"source"`
	Serial              uint64   `json:"serial"`
	IssuedAt            string   `json:"issued_at,omitempty"`
	Expires             string   `json:"expires"`                        // RFC3339; consumer rejects stale (D13)
	RevokedBuilderKeys  []string `json:"revoked_builder_keys,omitempty"` // builder key_ids
	RevokedAttestations []string `json:"revoked_attestations,omitempty"` // blake3 content-hashes
}

// ParseRevocationList reads a JSON revocation list, rejects unknown fields, and
// validates it against the embedded v1 JSON Schema.
func ParseRevocationList(r io.Reader) (*RevocationList, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read revocation list: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rl RevocationList
	if err := dec.Decode(&rl); err != nil {
		return nil, fmt.Errorf("decode revocation list: %w", err)
	}
	if err := validateAgainstSchema(data, revocationListSchemaV1, "revocation-list-v1.json"); err != nil {
		return nil, err
	}
	return &rl, nil
}
