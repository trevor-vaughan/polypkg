package schema

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

//go:embed jsonschema/pin-v1.json
var pinSchemaV1 []byte

// Pin is the per-generation pin record persisted as pin.json next to the
// generation's manifest.json. Its presence marks the generation as pinned
// (exempt from automatic GC). The metadata is operator-facing: who pinned
// it, when, and why.
type Pin struct {
	Schema       string    `json:"schema"`
	Generation   int       `json:"generation"`
	PinnedAt     time.Time `json:"pinned_at"`
	PinnedBy     string    `json:"pinned_by"`
	PinnedReason string    `json:"pinned_reason,omitempty"`
}

// ParsePin reads a JSON pin record from r, validates it against the v1 JSON
// Schema, and returns the typed representation.
func ParsePin(r io.Reader) (*Pin, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read pin: %w", err)
	}
	if err := validateAgainstSchema(data, pinSchemaV1, "pin-v1.json"); err != nil {
		return nil, err
	}
	var p Pin
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshal pin: %w", err)
	}
	return &p, nil
}
