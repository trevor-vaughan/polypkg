package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/tailscale/hujson"
)

// standardizeJSONC wraps hujson.Standardize to translate its error wording
// into polypkg's canonical jsonc-error vocabulary.
//
//   - An "after top-level value" error means the input contained trailing
//     non-comment data after the root JSON value. This is translated into
//     "jsonc decode: unexpected data after root value" for consistency.
//   - An EOF-bearing error on an input that contains only whitespace and
//     comments means "empty document with annotations" — treated as empty
//     (nil bytes) so the caller routes through schema validation against
//     the zero-value struct.
//   - An EOF-bearing error on an input that contains JSON characters means
//     a truncated document — surfaced as a "jsonc parse" error so the user
//     sees a syntax diagnostic rather than a confusing schema diagnostic.
func standardizeJSONC(data []byte) ([]byte, error) {
	canon, err := hujson.Standardize(data)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "after top-level value") {
			return nil, errors.New("jsonc decode: unexpected data after root value")
		}
		if strings.Contains(msg, "EOF") {
			if hasOnlyCommentsOrWhitespace(data) {
				// Empty or comment-only input — treat as empty.
				return nil, nil
			}
			// JSON content was present but the document was cut short.
			return nil, fmt.Errorf("jsonc parse: %w", err)
		}
		return nil, fmt.Errorf("jsonc parse: %w", err)
	}
	return canon, nil
}

// hasOnlyCommentsOrWhitespace returns true if data contains no JSON content —
// only whitespace and JWCC comments. It is used after hujson.Standardize
// returns an EOF error to distinguish a truly-empty document (annotations
// only) from a truncated document (real JSON content cut short).
func hasOnlyCommentsOrWhitespace(data []byte) bool {
	i := 0
	for i < len(data) {
		switch {
		case data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r':
			i++
		case i+1 < len(data) && data[i] == '/' && data[i+1] == '/':
			// Line comment: skip to next newline or end.
			i += 2
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case i+1 < len(data) && data[i] == '/' && data[i+1] == '*':
			// Block comment: skip to */ or end. Unterminated block comments
			// are themselves a parse error, so return false to surface them.
			i += 2
			closed := false
			for i+1 < len(data) {
				if data[i] == '*' && data[i+1] == '/' {
					i += 2
					closed = true
					break
				}
				i++
			}
			if !closed {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// format identifies the parser to dispatch to.
type format int

const (
	formatUnknown format = iota
	formatYAML
	formatJSONC
)

// parseFormat returns the parser to use for a given source name. An empty
// name maps to YAML for backward compatibility with callers that have no
// filename in hand. Any extension other than the ones listed maps to
// formatUnknown, which the dispatcher surfaces as an "unsupported format"
// error.
func parseFormat(name string) format {
	if name == "" {
		return formatYAML
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".yaml", ".yml":
		return formatYAML
	case ".jsonc", ".json":
		return formatJSONC
	default:
		return formatUnknown
	}
}

// isEffectivelyEmpty reports whether b contains only ASCII whitespace.
// For the JSONC path, this is called after hujson.Standardize, so any
// comments have already been replaced with whitespace — a comment-only
// file is effectively empty.
func isEffectivelyEmpty(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}

// parseProfileJSONC parses a JSONC profile. The pipeline mirrors
// parseProfileYAML except for the format-specific decode:
//
//  1. hujson.Standardize strips JSONC syntactic sugar.
//  2. If the standardized bytes are empty/whitespace, validate the zero-value
//     Profile against the schema to produce diagnostics.
//  3. Otherwise validate the generic JSON against the schema first (so
//     structural errors report field-level messages, not Go type noise).
//  4. On validation success, decode into the typed struct with
//     DisallowUnknownFields().
func parseProfileJSONC(data []byte, name string) (*Profile, error) {
	canon, err := standardizeJSONC(data)
	if err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}

	var p Profile
	if len(canon) > 0 && !isEffectivelyEmpty(canon) {
		// Validate the raw JSON before typed decode so structural errors surface
		// as schema diagnostics rather than Go type system messages.
		if err := validateProfileSchema(canon, name); err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(canon))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("jsonc decode: %w", err)
		}
		return &p, nil
	}

	// Empty/comment-only input: report as empty rather than running schema
	// validation and producing a verbose list of every required field.
	return nil, profileEmptyError(name)
}

// parsePackageJSONC parses a JSONC package recipe. Same pipeline as
// parseProfileJSONC; the PackageAction.UnmarshalJSON method (below) handles
// the !starlark envelope and action-param number normalization.
func parsePackageJSONC(data []byte) (*Package, error) {
	canon, err := standardizeJSONC(data)
	if err != nil {
		return nil, err
	}

	var p Package
	if len(canon) > 0 && !isEffectivelyEmpty(canon) {
		dec := json.NewDecoder(bytes.NewReader(canon))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("jsonc decode: %w", err)
		}
	}

	jsonBytes, err := json.Marshal(&p)
	if err != nil {
		return nil, fmt.Errorf("marshal for validation: %w", err)
	}
	if err := validateAgainstSchema(jsonBytes, packageSchemaV1, "package-v1.json"); err != nil {
		return nil, err
	}
	return &p, nil
}

// UnmarshalJSON decodes a PackageAction from JSON. Settings from the outer
// json.Decoder (UseNumber, DisallowUnknownFields) do not propagate to nested
// UnmarshalJSON implementations, so this method constructs its own decoder.
// Manual key-walking mirrors the YAML side's UnmarshalYAML for parallel
// error messages.
func (v *PackageAction) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	dec.DisallowUnknownFields()

	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("action decode: %w", err)
	}

	for key, rawVal := range raw {
		switch key {
		case "phase":
			if err := json.Unmarshal(rawVal, &v.Phase); err != nil {
				return fmt.Errorf("action field phase: %w", err)
			}
		case "action":
			if err := json.Unmarshal(rawVal, &v.Action); err != nil {
				return fmt.Errorf("action field action: %w", err)
			}
		case "drift":
			if err := json.Unmarshal(rawVal, &v.Drift); err != nil {
				return fmt.Errorf("action field drift: %w", err)
			}
		case "params":
			params, err := decodeParamsJSON(rawVal)
			if err != nil {
				return err
			}
			v.Params = params
		default:
			return fmt.Errorf("unknown action field %q", key)
		}
	}
	return nil
}

// decodeParamsJSON decodes an action-params map. Scalars and arrays decode
// normally with number normalization; JSON objects are checked for the
// {"!starlark": "<expr>"} envelope and decoded as a literal map[string]any
// otherwise.
//
// Explicit `null` is rejected to match the YAML path's "action params must be
// a mapping" diagnostic — `json.Unmarshal` of `null` into a map silently
// produces a nil map, which would otherwise diverge from YAML.
func decodeParamsJSON(data json.RawMessage) (map[string]any, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, errors.New("action params must be a mapping")
	}
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("action params: %w", err)
	}

	out := make(map[string]any, len(raw))
	for k, rv := range raw {
		val, err := decodeParamValueJSON(rv)
		if err != nil {
			return nil, fmt.Errorf("action param %q: %w", k, err)
		}
		out[k] = val
	}
	return out, nil
}

// decodeParamValueJSON returns the Go value for a single action-param.
// Objects are inspected for a "!starlark" key:
//   - present  -> validated as a {"!starlark": "<string>"} envelope.
//   - absent   -> decoded as a literal map[string]any with number
//     normalization recursing into nested objects/arrays.
//
// Scalars and arrays decode normally with json.Number normalized to
// int64 if integral, else float64.
func decodeParamValueJSON(data json.RawMessage) (any, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		// Peek the object's keys to decide envelope vs literal map.
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &probe); err != nil {
			return nil, fmt.Errorf("action param decode: %w", err)
		}
		if _, hasStarlark := probe["!starlark"]; hasStarlark {
			return decodeStarlarkEnvelope(trimmed)
		}
		// Literal nested map — recurse into each value (preserves number
		// normalization and lets nested objects also carry envelopes).
		out := make(map[string]any, len(probe))
		for k, rv := range probe {
			v, err := decodeParamValueJSON(rv)
			if err != nil {
				return nil, fmt.Errorf("key %q: %w", k, err)
			}
			out[k] = v
		}
		return out, nil
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var val any
	if err := dec.Decode(&val); err != nil {
		return nil, fmt.Errorf("action param decode: %w", err)
	}
	return normalizeJSONValue(val), nil
}

// decodeStarlarkEnvelope expects exactly {"!starlark": "<string>"}. Any
// other shape (extra keys, non-string value, missing key) is an error.
func decodeStarlarkEnvelope(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("starlark envelope: %w", err)
	}
	if len(raw) != 1 {
		return nil, fmt.Errorf("invalid starlark envelope shape: expected single key !starlark, got %d keys", len(raw))
	}
	exprRaw, ok := raw["!starlark"]
	if !ok {
		return nil, errors.New("invalid starlark envelope shape: missing !starlark key")
	}
	var expr string
	if err := json.Unmarshal(exprRaw, &expr); err != nil {
		return nil, fmt.Errorf("invalid starlark envelope shape: value must be a string: %w", err)
	}
	return StarlarkExpr{Source: expr}, nil
}

// normalizeJSONValue walks a decoded value and converts every json.Number
// to the same Go type that gopkg.in/yaml.v3 produces for an equivalent
// scalar in an interface{}-typed context: integral numbers that fit in
// a machine int become int, integers that overflow int but fit float64
// become float64, and non-integral numbers become float64. Maintaining
// this parity is what makes the format-equivalence matrix tests succeed
// under reflect.DeepEqual.
func normalizeJSONValue(v any) any {
	switch t := v.(type) {
	case json.Number:
		if i, err := t.Int64(); err == nil {
			// Demote to int if it fits, matching YAML's interface{} decoding.
			if int64(int(i)) == i {
				return int(i)
			}
			return i
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return t
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[k] = normalizeJSONValue(vv)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			out[i] = normalizeJSONValue(vv)
		}
		return out
	default:
		return v
	}
}
