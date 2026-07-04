package schema

import (
	"encoding/json"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that (un)marshals as a Go duration string ("2s").
type Duration time.Duration

// UnmarshalYAML parses a Go duration string.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalJSON emits the duration as a string for JSON-Schema validation.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON parses a Go duration string. Parallel to UnmarshalYAML so
// the JSONC profile path produces the same Duration value YAML does.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// StarlarkLimits are the resource caps for !starlark evaluation. A zero field
// means "use the default" (see ResolveStarlarkLimits).
type StarlarkLimits struct {
	MaxSteps       uint64   `yaml:"max_steps,omitempty"        json:"max_steps,omitempty"`
	Timeout        Duration `yaml:"timeout,omitempty"          json:"timeout,omitempty"`
	MaxMemoryBytes uint64   `yaml:"max_memory_bytes,omitempty" json:"max_memory_bytes,omitempty"`
	MaxOutputBytes int      `yaml:"max_output_bytes,omitempty" json:"max_output_bytes,omitempty"`
}

// DefaultStarlarkLimits returns the safe defaults applied when no profile block
// (or no field) is set.
func DefaultStarlarkLimits() StarlarkLimits {
	return StarlarkLimits{
		MaxSteps:       10_000_000,
		Timeout:        Duration(2 * time.Second),
		MaxMemoryBytes: 64 << 20, // 64 MiB
		MaxOutputBytes: 64 << 10, // 64 KiB
	}
}

// ResolveStarlarkLimits fills any zero field of s with its default. A nil s
// yields all defaults.
func ResolveStarlarkLimits(s *StarlarkLimits) StarlarkLimits {
	out := DefaultStarlarkLimits()
	if s == nil {
		return out
	}
	if s.MaxSteps != 0 {
		out.MaxSteps = s.MaxSteps
	}
	if s.Timeout != 0 {
		out.Timeout = s.Timeout
	}
	if s.MaxMemoryBytes != 0 {
		out.MaxMemoryBytes = s.MaxMemoryBytes
	}
	if s.MaxOutputBytes != 0 {
		out.MaxOutputBytes = s.MaxOutputBytes
	}
	return out
}
