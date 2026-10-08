package schema

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

//go:embed jsonschema/package-v1.json
var packageSchemaV1 []byte

// Relation is a named dependency/capability reference with an optional semver
// constraint. An empty Version means "any version".
type Relation struct {
	Name    string `yaml:"name"              json:"name"`
	Version string `yaml:"version,omitempty" json:"version,omitempty"`
}

// Package is the parsed polypkg.yaml from inside a package tarball.
type Package struct {
	Schema  string `yaml:"schema"                json:"schema"`
	Name    string `yaml:"name"                  json:"name"`
	Version string `yaml:"version"               json:"version"`
	// Platform is <os>/<arch>[/<variant>]; "" means platform-agnostic. A
	// recipe's explicit platform: "" means the same as omitting the key; an
	// index entry omits the key and never spells "" (index-v3.json refuses it).
	Platform    string          `yaml:"platform,omitempty"    json:"platform,omitempty"`
	Title       string          `yaml:"title,omitempty"       json:"title,omitempty"`
	Description string          `yaml:"description,omitempty" json:"description,omitempty"`
	Depends     []Relation      `yaml:"depends,omitempty"     json:"depends,omitempty"`
	Recommends  []Relation      `yaml:"recommends,omitempty"  json:"recommends,omitempty"`
	Suggests    []Relation      `yaml:"suggests,omitempty"    json:"suggests,omitempty"`
	Provides    []Relation      `yaml:"provides,omitempty"    json:"provides,omitempty"`
	Conflicts   []Relation      `yaml:"conflicts,omitempty"   json:"conflicts,omitempty"`
	Obsoletes   []Relation      `yaml:"obsoletes,omitempty"   json:"obsoletes,omitempty"`
	Actions     []PackageAction `yaml:"actions"               json:"actions"`
}

// PackageAction is one action invocation declared by the package.
type PackageAction struct {
	Phase  string         `yaml:"phase"           json:"phase"`
	Action string         `yaml:"action"          json:"action"`
	Drift  string         `yaml:"drift,omitempty" json:"drift,omitempty"`
	Params map[string]any `yaml:"params"          json:"params"`
}

// StarlarkExpr is an action-param value computed by a !starlark snippet rather than
// a literal. The runner evaluates Source at dispatch time (see internal/starlarkeval).
type StarlarkExpr struct {
	Source string
}

// MarshalJSON emits the snippet source as a JSON string so the package
// JSON-Schema validation (params values are unconstrained) still passes.
func (e StarlarkExpr) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.Source)
}

// UnmarshalYAML decodes an action, capturing any param value tagged !starlark as a
// StarlarkExpr while decoding every other value normally. It rejects unknown
// action keys, preserving the strictness the package decoder enforces elsewhere.
func (v *PackageAction) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("action must be a mapping, got %v", node.Kind)
	}
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1]
		switch key {
		case "phase":
			if err := val.Decode(&v.Phase); err != nil {
				return err
			}
		case "action":
			if err := val.Decode(&v.Action); err != nil {
				return err
			}
		case "drift":
			if err := val.Decode(&v.Drift); err != nil {
				return err
			}
		case "params":
			if val.Kind != yaml.MappingNode {
				return fmt.Errorf("action params must be a mapping")
			}
			v.Params = make(map[string]any, len(val.Content)/2)
			for j := 0; j < len(val.Content); j += 2 {
				pk := val.Content[j].Value
				pv := val.Content[j+1]
				if pv.Tag == "!starlark" {
					v.Params[pk] = StarlarkExpr{Source: pv.Value}
					continue
				}
				var anyVal any
				if err := pv.Decode(&anyVal); err != nil {
					return err
				}
				v.Params[pk] = anyVal
			}
		default:
			return fmt.Errorf("unknown action field %q", key)
		}
	}
	return nil
}

// ParsePackage reads a polypkg package recipe from r, validates it against
// the polypkg.package/v1 JSON Schema, and returns a typed Package. The name
// argument is the source filename or path; its extension selects the
// parser:
//
//	.yaml, .yml, ""        -> strict YAML 1.2 (anchors banned)
//	.jsonc, .json          -> JSONC (JSON with comments + trailing commas)
//	anything else          -> error
//
// Empty name falls back to YAML for backward compatibility.
func ParsePackage(r io.Reader, name string) (*Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read package: %w", err)
	}
	switch parseFormat(name) {
	case formatYAML:
		return parsePackageYAML(data)
	case formatJSONC:
		return parsePackageJSONC(data)
	default:
		ext := filepath.Ext(name)
		if ext == "" {
			return nil, fmt.Errorf("unsupported format: %q has no extension (want .yaml, .yml, .jsonc, or .json)", name)
		}
		return nil, fmt.Errorf("unsupported format: %s (want .yaml, .yml, .jsonc, or .json)", ext)
	}
}

func parsePackageYAML(data []byte) (*Package, error) {
	var p Package
	if !isEffectivelyEmpty(data) {
		// First parse generically to detect anchors.
		var node yaml.Node
		if err := yaml.Unmarshal(data, &node); err != nil {
			return nil, fmt.Errorf("yaml parse: %w", err)
		}
		if hasAnchors(&node) {
			return nil, errors.New("yaml anchors are not permitted in polypkg package specs")
		}

		// Now parse into the typed struct with strict unknown-field rejection.
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				// All non-whitespace was YAML comments; fall through to schema
				// validation against the zero-value Package (parity with the
				// JSONC path's empty-input handling).
				p = Package{}
			} else {
				return nil, fmt.Errorf("yaml decode: %w", plainYAMLDecodeError(err))
			}
		}
	}

	// Validate against the JSON Schema by round-tripping through JSON.
	jsonBytes, err := json.Marshal(&p)
	if err != nil {
		return nil, fmt.Errorf("marshal for validation: %w", err)
	}
	if err := validateAgainstSchema(jsonBytes, packageSchemaV1, "package-v1.json"); err != nil {
		return nil, err
	}
	return &p, nil
}
