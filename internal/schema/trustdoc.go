package schema

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
)

//go:embed jsonschema/trust-v2.json
var trustSchemaV2 []byte

// TrustKey is one signing key listed in a polypkg.trust/v2 document.
type TrustKey struct {
	ID     string   `json:"id"`
	Pubkey string   `json:"pubkey"`
	Roles  []string `json:"roles"`
}

// TrustDoc is a source's signed statement of which keys may currently sign for
// it (polypkg.trust/v2). Callers MUST verify its signature before parsing.
type TrustDoc struct {
	Schema   string     `json:"schema"`
	Source   string     `json:"source"`
	Serial   uint64     `json:"serial"`
	IssuedAt string     `json:"issued_at,omitempty"`
	Expires  string     `json:"expires"` // RFC3339; consumer rejects stale (D13)
	Keys     []TrustKey `json:"keys"`
	Revoked  []string   `json:"revoked,omitempty"`
}

// ParseTrustDoc reads a JSON trust document, rejects unknown fields, and
// validates it against the embedded v2 JSON Schema.
func ParseTrustDoc(r io.Reader) (*TrustDoc, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read trust document: %w", err)
	}
	if err := checkNotNewer(data, trustSchemaV2); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var td TrustDoc
	if err := dec.Decode(&td); err != nil {
		return nil, fmt.Errorf("decode trust document: %w", err)
	}
	if err := validateAgainstSchema(data, trustSchemaV2, "trust-v2.json"); err != nil {
		return nil, err
	}
	return &td, nil
}
