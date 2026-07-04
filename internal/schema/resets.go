package schema

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
)

//go:embed jsonschema/resets-v1.json
var resetsSchemaV1 []byte

// Resets is the operator-authored queue of config paths to restore to package
// defaults on the next apply. It is consumed and cleared by apply.
type Resets struct {
	Schema string   `json:"schema"`
	Scope  string   `json:"scope"`
	Paths  []string `json:"paths"`
}

// ParseResets reads a JSON resets record from r, validates it against the v1
// JSON Schema, and returns the typed representation with a non-nil Paths.
func ParseResets(r io.Reader) (*Resets, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read resets: %w", err)
	}
	if err := validateAgainstSchema(data, resetsSchemaV1, "resets-v1.json"); err != nil {
		return nil, err
	}
	var rs Resets
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("unmarshal resets: %w", err)
	}
	if rs.Paths == nil {
		rs.Paths = []string{}
	}
	return &rs, nil
}
