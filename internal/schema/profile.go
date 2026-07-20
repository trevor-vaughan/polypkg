// Package schema defines polypkg's wire formats (profile spec and
// signed manifest) with strict validation.
package schema

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// reYAMLLineN matches the line number embedded in gopkg.in/yaml.v3 error
// messages, e.g. "yaml: line 4: found character that cannot start any token".
var reYAMLLineN = regexp.MustCompile(`yaml: line (\d+):`)

// profileEmptyError returns the standard "profile is empty" error message.
// name is the user-visible profile file name.
func profileEmptyError(name string) error {
	return fmt.Errorf("profile %s is empty; a profile needs at least schema, name, scopes, and sources (see the README quickstart)", name)
}

// yamlTabError checks whether a yaml.Unmarshal error is caused by tab
// indentation and, if so, replaces the message with a plain-English
// alternative. Two yaml.v3 error messages indicate tab usage:
//   - "found character that cannot start any token" (tab in value context)
//   - "found a tab character that violates indentation" (tab as indent)
//
// In both cases the line is verified to actually start with a tab (after any
// leading spaces) before substituting the message; if verification fails the
// original error is returned unchanged so that unrelated token errors are
// never degraded.
func yamlTabError(err error, data []byte, name string) error {
	msg := err.Error()
	isTabMsg := strings.Contains(msg, "found character that cannot start any token") ||
		strings.Contains(msg, "found a tab character that violates indentation")
	if !isTabMsg {
		return err
	}
	m := reYAMLLineN.FindStringSubmatch(msg)
	if m == nil {
		return err
	}
	// Parse line number (1-based).
	lineNum, err := strconv.Atoi(m[1])
	if err != nil || lineNum <= 0 {
		return err
	}
	lines := bytes.Split(data, []byte("\n"))
	if lineNum > len(lines) {
		return err
	}
	lineBytes := lines[lineNum-1]
	// Trim leading spaces (ordinary indentation); the first remaining character
	// must be a tab for this to be a tab-indentation error.
	trimmed := bytes.TrimLeft(lineBytes, " ")
	if len(trimmed) == 0 || trimmed[0] != '\t' {
		return err
	}
	return fmt.Errorf("profile %s: line %d: YAML does not allow tab indentation; use spaces", name, lineNum)
}

//go:embed jsonschema/profile-v1.json
var profileSchemaV1 []byte

// Profile is the typed representation of a polypkg.spec/v1 profile.
type Profile struct {
	Schema      string                           `yaml:"schema"             json:"schema"`
	Name        string                           `yaml:"name"               json:"name"`
	Description string                           `yaml:"description,omitempty" json:"description,omitempty"`
	Scopes      map[string]ScopeSpec             `yaml:"scopes"             json:"scopes"`
	Sources     SourcesSpec                      `yaml:"sources"            json:"sources"`
	Variants    map[string]string                `yaml:"variants,omitempty" json:"variants,omitempty"`
	Packages    map[string]map[string]PackageRef `yaml:"packages,omitempty" json:"packages,omitempty"`
	Starlark    *StarlarkLimits                  `yaml:"starlark,omitempty" json:"starlark,omitempty"`
	Retention   *Retention                       `yaml:"retention,omitempty" json:"retention,omitempty"`
	Recommends  *RecommendsPolicy                `yaml:"recommends,omitempty" json:"recommends,omitempty"`
	Attestation *AttestationPolicy               `yaml:"attestation,omitempty" json:"attestation,omitempty"`
}

// AttestationPolicy is the consumer's attestation posture (D8). The static
// setting is the user's standing approval channel — apply is non-interactive.
type AttestationPolicy struct {
	Policy string `yaml:"policy" json:"policy"` // warn (default) | require | off
}

// Retention configures the retention thresholds the gc subsystem applies
// opportunistically after each apply. Count and Age are independent
// thresholds; a generation survives if either retains it. See
// apply-semantics §4.3.
type Retention struct {
	Count int    `yaml:"count" json:"count"`
	Age   string `yaml:"age,omitempty" json:"age,omitempty"`
}

// RecommendsPolicy controls whether weak dependencies (Recommends) are
// installed. An absent block means install (default on); a present block with
// install:false suppresses weak installs while still allowing them to be
// reported.
type RecommendsPolicy struct {
	Install bool `yaml:"install" json:"install"`
}

// ScopeSpec describes one scope's substrate selection.
type ScopeSpec struct {
	Substrate string `yaml:"substrate"         json:"substrate"`
	Prefix    string `yaml:"prefix,omitempty"  json:"prefix,omitempty"`
}

// SourcesSpec describes available source backends and their preference order.
type SourcesSpec struct {
	Order   []string                 `yaml:"order"    json:"order"`
	Sources map[string]SourceBackend `yaml:",inline"  json:"-"`
}

// MarshalJSON produces a flat JSON object containing "order" plus each named
// source backend so that the JSON Schema can validate trust_root and other
// security-critical fields on every backend.
func (s SourcesSpec) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(s.Sources)+1)
	for k, v := range s.Sources {
		m[k] = v
	}
	m["order"] = s.Order
	return json.Marshal(m)
}

// UnmarshalJSON decodes the flat JSON sources object, where "order" is the
// known key and all other keys are source backend names. This mirrors what
// yaml:",inline" provides for YAML.
func (s *SourcesSpec) UnmarshalJSON(data []byte) error {
	// Decode into a raw map first to separate known keys from backend names.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if orderRaw, ok := raw["order"]; ok {
		if err := json.Unmarshal(orderRaw, &s.Order); err != nil {
			return fmt.Errorf("sources.order: %w", err)
		}
	}
	for k, v := range raw {
		if k == "order" {
			continue
		}
		var backend SourceBackend
		if err := json.Unmarshal(v, &backend); err != nil {
			return fmt.Errorf("source %q: %w", k, err)
		}
		if s.Sources == nil {
			s.Sources = make(map[string]SourceBackend)
		}
		s.Sources[k] = backend
	}
	return nil
}

// SourceBackend describes one source backend configuration.
type SourceBackend struct {
	Type      string `yaml:"type"                json:"type"`
	URL       string `yaml:"url"                 json:"url"`
	TrustRoot string `yaml:"trust_root"          json:"trust_root"`
	// TrustDoc is an optional local path to a signed polypkg.trust/v2 document.
	// When set, it is used instead of fetching the document from the source
	// (the airgap / out-of-band path); it is verified identically.
	TrustDoc string `yaml:"trust_doc,omitempty" json:"trust_doc,omitempty"`
	// AcceptExpiryUntil is an optional RFC3339 deadline (phase 2e-1, spec
	// §10.9 E-3). When set, signed metadata for this source (index, trust
	// document, trust bundle, revocation list) that has EXPIRED is still
	// accepted as long as now is at or before this deadline — the freshness
	// bound is relaxed for a frozen air-gap mirror. It relaxes WALL-CLOCK
	// expiry ONLY: the monotonic anti-rollback serial floor is a separate gate
	// that still refuses a stale-lower-serial document. Grace is loud (a
	// SECURITY line on apply/plan + a metadata.expiry_graced audit event).
	AcceptExpiryUntil string `yaml:"accept_expiry_until,omitempty" json:"accept_expiry_until,omitempty"`
	// Attestation is an optional per-source attestation gate (phase 2d-1,
	// spec §8/§10.6). Additive to the global AttestationPolicy: the global
	// policy gates ABSENCE of any attestation, this gates per-predicate
	// PRESENCE and verification tier. Absent ⇒ the source is ungated.
	Attestation *SourceAttestationPolicy `yaml:"attestation,omitempty" json:"attestation,omitempty"`
	// SigstoreRoot is an optional consumer-pinned sigstore trust root (phase
	// 2e-5, spec §10.9 E-6). When set it is AUTHORITATIVE for this source's
	// sigstore-format carried attestations: the planner selects trusted material
	// from this pin (window-checked by the bundle's integrated time) and the
	// source-mirrored root is NOT consulted, closing the D-4 G1 chain-degradation
	// asymmetry. When absent, the mirrored root is used (today's behavior).
	SigstoreRoot *SigstoreRoot `yaml:"sigstore_root,omitempty" json:"sigstore_root,omitempty"`
}

// AttestationTierOff is the only per-source attestation tier value in v1
// (phase 2d-3, spec §8.2/§10.8). It DISABLES the source's attestation gating:
// an unattested package installs (the effective absence policy becomes "off")
// and the require gate + posture floor are skipped — but a PRESENT attestation
// is still hard-verified (D-C10), and every apply emits a loud, unsuppressible
// warning and records the disabled gate distinctly (GateDisabled). It is the
// OPPOSITE of the pre-existing global attestation.policy: off, which installs
// unattested packages SILENTLY. full/offline-ok are the implicit default when
// tier is absent; transport-ok is deferred (spec §10.8 G-3).
const AttestationTierOff = "off"

// SourceAttestationPolicy is a source's per-predicate attestation gate
// (phase 2d-1). Each Require entry must be present and verified at an anchored
// tier; Builders is the consumer-authoritative identity allow-list. Tier: off
// (phase 2d-3) DISABLES the gate for the source (mutually exclusive with
// Require/Builders — enforced by the schema); see AttestationTierOff.
type SourceAttestationPolicy struct {
	Require  []string      `yaml:"require,omitempty"  json:"require,omitempty"`
	Builders *BuilderAllow `yaml:"builders,omitempty" json:"builders,omitempty"`
	Tier     string        `yaml:"tier,omitempty"     json:"tier,omitempty"`
}

// BuilderAllow is the consumer allow-list of trusted builder identities
// (D-P3, threat G1). An empty allow-list trusts the source's anchored-bundle
// key governance — a weaker posture that does not mitigate G1.
type BuilderAllow struct {
	Allow []BuilderAllowEntry `yaml:"allow" json:"allow"`
}

// BuilderAllowEntry is one allowed identity: exactly one of Key (an ed25519
// builder public key matching a builder-verified binding) or Sigstore (a
// Fulcio identity matching a verified-offline binding). NOTE the two kinds are
// NOT equally strong against a compromised source: Key pins the actual public
// key bytes (a publisher cannot forge a signature under a key it does not
// hold), whereas Sigstore pins only issuer+SAN strings whose authenticity rests
// on the source-mirrored Fulcio root — a source that controls its trust bundle
// can mint a cert bearing any SAN. Prefer Key for hard G1 protection; a
// consumer-pinned sigstore root is deferred hardening (spec §10.6/§12).
type BuilderAllowEntry struct {
	Key      string         `yaml:"key,omitempty"      json:"key,omitempty"`
	Sigstore *SigstoreAllow `yaml:"sigstore,omitempty" json:"sigstore,omitempty"`
}

// SigstoreAllow is a Fulcio certificate-identity allow-list entry. Issuer
// matches exactly; SAN matches exactly or, when it ends with a single "*", by
// prefix. Its G1 protection is only as strong as the source's mirrored Fulcio
// root (see BuilderAllowEntry) — it does not defend against a fully-compromised
// source the way a pinned Key does.
type SigstoreAllow struct {
	Issuer string `yaml:"issuer" json:"issuer"`
	SAN    string `yaml:"san"    json:"san"`
}

// PackageRef references a package with version constraints.
type PackageRef struct {
	Version string `yaml:"version"           json:"version"`
	Source  string `yaml:"source,omitempty"  json:"source,omitempty"`
}

// ParseProfile reads a profile spec from r, validates it against the
// polypkg.spec/v1 JSON Schema, and returns a typed Profile. The name
// argument is the source filename or path; its extension selects the
// parser:
//
//	.yaml, .yml, ""        -> strict YAML 1.2 (anchors banned)
//	.jsonc, .json          -> JSONC (JSON with comments + trailing commas)
//	anything else          -> error
//
// Empty name falls back to YAML for backward compatibility.
func ParseProfile(r io.Reader, name string) (*Profile, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	switch parseFormat(name) {
	case formatYAML:
		return parseProfileYAML(data, name)
	case formatJSONC:
		return parseProfileJSONC(data, name)
	default:
		ext := filepath.Ext(name)
		if ext == "" {
			return nil, fmt.Errorf("unsupported format: %q has no extension (want .yaml, .yml, .jsonc, or .json)", name)
		}
		return nil, fmt.Errorf("unsupported format: %s (want .yaml, .yml, .jsonc, or .json)", ext)
	}
}

func parseProfileYAML(data []byte, name string) (*Profile, error) {
	var p Profile
	if !isEffectivelyEmpty(data) {
		// First parse generically to detect anchors and structural errors.
		var node yaml.Node
		if err := yaml.Unmarshal(data, &node); err != nil {
			return nil, yamlTabError(fmt.Errorf("profile %s: yaml parse: %w", name, err), data, name)
		}
		if hasAnchors(&node) {
			return nil, errors.New("yaml anchors are not permitted in polypkg profile specs")
		}

		// Validate against the JSON Schema by converting the generic value to
		// JSON first. This catches structural errors (wrong types, missing
		// required fields) with schema-level diagnostics rather than Go type
		// system noise. We do this BEFORE the typed decode so that e.g.
		// `packages: [hello]` (a list where a map is required) reports
		// "/packages: ..." rather than leaking "!!seq" / "schema.PackageRef".
		var generic any
		if err := node.Decode(&generic); err != nil {
			// Syntax error: forward with name for context, but no type names.
			return nil, yamlTabError(fmt.Errorf("profile %s: yaml parse: %w", name, err), data, name)
		}
		if generic == nil {
			// Comment-only YAML decodes to nil — treat as empty.
			return nil, profileEmptyError(name)
		}
		genericJSON, err := json.Marshal(generic)
		if err != nil {
			return nil, fmt.Errorf("marshal for validation: %w", err)
		}
		if err := validateProfileSchema(genericJSON, name); err != nil {
			return nil, err
		}

		// Schema passed; now decode into the typed struct with strict
		// unknown-field rejection. After schema validation this path should
		// only fail for type-system details the schema cannot express
		// (e.g. custom UnmarshalYAML logic).
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				// All non-whitespace was YAML comments; treat as empty.
				p = Profile{}
			} else {
				return nil, fmt.Errorf("yaml decode: %w", err)
			}
		}
		return &p, nil
	}

	// Empty input (only whitespace): report as empty rather than running schema
	// validation and producing a verbose list of every required field.
	return nil, profileEmptyError(name)
}

// validateProfileSchema validates instanceJSON against profile-v1.json and
// returns a friendly error if validation fails. The name argument is the
// user-visible profile file name included in the error message.
func validateProfileSchema(instanceJSON []byte, name string) error {
	if err := validateAgainstSchema(instanceJSON, profileSchemaV1, "profile-v1.json"); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			return profileFriendlyError(name, ve)
		}
		return err
	}
	return nil
}

// hasAnchors reports whether node or any of its descendants use YAML anchors
// or aliases.  Anchors expand silently and can be used to bypass field limits,
// so polypkg rejects them outright.
func hasAnchors(node *yaml.Node) bool {
	if node.Anchor != "" || node.Alias != nil {
		return true
	}
	return slices.ContainsFunc(node.Content, hasAnchors)
}
