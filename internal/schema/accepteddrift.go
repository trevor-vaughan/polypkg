package schema

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
)

//go:embed jsonschema/accepted-drift-v1.json
var acceptedDriftSchemaV1 []byte

// AcceptedDrift records operator-accepted drift overrides: for each named path,
// the live state at the moment accept-drift was run. It is keyed by generation
// so a new generation (which resets the baseline) invalidates the whole record.
type AcceptedDrift struct {
	Schema     string                  `json:"schema"`
	Generation int                     `json:"generation"`
	Paths      map[string]AcceptedPath `json:"paths"`
}

// AcceptedPath captures the live state of one accepted path at acceptance time.
// Drift detection treats the path as not-drifted while the current observed
// state still matches this snapshot.
type AcceptedPath struct {
	Expected Expected `json:"expected"`
	Stat     StatInfo `json:"stat"`
}

// ParseAcceptedDrift reads a JSON accepted-drift record from r, validates it
// against the v1 JSON Schema, and returns the typed representation with a
// non-nil Paths.
func ParseAcceptedDrift(r io.Reader) (*AcceptedDrift, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read accepted-drift: %w", err)
	}
	if err := validateAgainstSchema(data, acceptedDriftSchemaV1, "accepted-drift-v1.json"); err != nil {
		return nil, err
	}
	var a AcceptedDrift
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("unmarshal accepted-drift: %w", err)
	}
	if a.Paths == nil {
		a.Paths = map[string]AcceptedPath{}
	}
	return &a, nil
}
