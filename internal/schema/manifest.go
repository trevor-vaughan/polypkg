package schema

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/gowebpki/jcs"
)

//go:embed jsonschema/manifest-v2.json
var manifestSchemaV2 []byte

// Manifest is the signed declarative resolution result.
type Manifest struct {
	Schema         string          `json:"schema"`
	Generation     int             `json:"generation"`
	Scope          string          `json:"scope"`
	WeakDepsPolicy string          `json:"weak_deps_policy,omitempty"`
	ProducedBy     ProducedBy      `json:"produced_by"`
	Entries        []ManifestEntry `json:"entries"`
}

// ProducedBy describes which polypkg invocation produced the manifest.
type ProducedBy struct {
	Tool      string    `json:"tool"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Host      string    `json:"host"`
}

// AttestationState records the install-time attestation verdict for one
// package (D11). Only "verified" or "unattested" are ever persisted for the
// native chain — a failed native verification never installs. CarriedBindings
// records any external provenance digest-bound to the installed bytes at a
// bound-but-unverified tier (builder-signature verification is phase 2c).
type AttestationState struct {
	Status          string           `json:"status"`                     // "verified" | "unattested"
	PredicateTypes  []string         `json:"predicate_types,omitempty"`  // verified predicate URIs
	AttestationHash string           `json:"attestation_hash,omitempty"` // blake3:… of the verified att.json
	PolicyAtInstall string           `json:"policy_at_install"`          // warn | require | off
	CarriedBindings []CarriedBinding `json:"carried_bindings,omitempty"` // external provenance bound to installed bytes
}

// CarriedBinding records that a carried external attestation was digest-bound to
// the bytes that actually installed (two-point binding P6, install half). Tier
// reflects how far verification went: at phase 2b-3 the builder/DSSE signature
// is not yet checked, so a bound carried attestation is "bound-unverified" — its
// subjects provably describe the installed bytes, but the external signer is not
// yet trusted.
type CarriedBinding struct {
	PredicateType string `json:"predicate_type"`
	Format        string `json:"format"`
	SubjectScope  string `json:"subject_scope"`
	Tier          string `json:"tier"`
}

// CarriedTierBoundUnverified is the tier of a carried attestation whose subjects
// are digest-bound to the installed bytes but whose external signature is not
// yet verified (that is phase 2c).
const CarriedTierBoundUnverified = "bound-unverified"

// ManifestEntry is one resolved package in the manifest.
type ManifestEntry struct {
	Name          string            `json:"name"`
	Version       string            `json:"version"`
	ContentHash   string            `json:"content_hash"`
	SourceURL     string            `json:"source_url,omitempty"`
	DependsOn     []string          `json:"depends_on,omitempty"`
	Weak          bool              `json:"weak,omitempty"`
	RecommendedBy []string          `json:"recommended_by,omitempty"`
	Attestation   *AttestationState `json:"attestation,omitempty"`
}

// Canonicalize returns the manifest serialized per RFC 8785 (JCS):
// lexicographically sorted keys, minimal escaping, no insignificant
// whitespace. These bytes are the input to signing.
func (m *Manifest) Canonicalize() ([]byte, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("jcs transform: %w", err)
	}
	return canonical, nil
}

// ParseManifest reads a JSON manifest from r, validates it against the v2
// JSON Schema, and returns the typed representation.
func ParseManifest(r io.Reader) (*Manifest, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	if err := validateAgainstSchema(data, manifestSchemaV2, "manifest-v2.json"); err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}
	return &m, nil
}
