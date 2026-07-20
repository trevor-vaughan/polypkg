package schema

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
)

//go:embed jsonschema/cli-result-v2.json
var cliResultSchemaV2 []byte

// CLIResult is the polypkg.cli-result/v2 envelope emitted by every action
// command under --format json. Plan and status do NOT use this envelope;
// they have bespoke schemas.
type CLIResult struct {
	Schema  string         `json:"schema"`
	Command string         `json:"command"`
	Status  string         `json:"status"`
	Data    map[string]any `json:"data,omitempty"`
	Error   string         `json:"error,omitempty"`
	Hint    string         `json:"hint,omitempty"`
}

// ParseCLIResult reads a JSON envelope from r, validates against the v2
// JSON Schema, and returns the typed representation.
func ParseCLIResult(r io.Reader) (*CLIResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read cli-result: %w", err)
	}
	if err := validateAgainstSchema(data, cliResultSchemaV2, "cli-result-v2.json"); err != nil {
		return nil, err
	}
	var cr CLIResult
	if err := json.Unmarshal(data, &cr); err != nil {
		return nil, fmt.Errorf("unmarshal cli-result: %w", err)
	}
	return &cr, nil
}
