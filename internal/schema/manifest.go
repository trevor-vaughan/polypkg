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
	GateDisabled    bool             `json:"gate_disabled,omitempty"`    // per-source tier: off disabled this source's gate at install (phase 2d-3, G8)
}

// CarriedBinding records that a carried external attestation was digest-bound to
// the bytes that actually installed (two-point binding P6, install half).
// Tier reflects how far verification went: bound-unverified (subjects
// digest-bound only), verified-transport-only (a DSSE envelope whose builder
// signature did not verify against a non-revoked, in-window bundle key, or a
// recognized but unsigned SBOM document), builder-verified (a bundle key
// valid at the attestation's build time verified the DSSE signature —
// VerifyingKeyID names it and, for SLSA provenance, BuilderIdentity records the
// builder.id), or verified-offline (a sigstore bundle's full certificate/Rekor/
// DSSE chain verified offline against a mirrored root — CertificateIdentity and
// CertificateIssuer record the Fulcio identity, phase 2c-3b).
type CarriedBinding struct {
	PredicateType       string `json:"predicate_type"`
	Format              string `json:"format"`
	SubjectScope        string `json:"subject_scope"`
	Tier                string `json:"tier"`
	VerifyingKeyID      string `json:"verifying_key_id,omitempty"`     // builder key id, set only when Tier == builder-verified
	BuilderIdentity     string `json:"builder_identity,omitempty"`     // SLSA builder.id, set only when Tier == builder-verified (phase 2c-1b)
	CertificateIdentity string `json:"certificate_identity,omitempty"` // Fulcio SAN, set only when Tier == verified-offline (phase 2c-3b)
	CertificateIssuer   string `json:"certificate_issuer,omitempty"`   // Fulcio OIDC issuer, set only when Tier == verified-offline (phase 2c-3b)
	AttestationHash     string `json:"attestation_hash,omitempty"`     // blake3:<hex> content-hash of this carried attestation; recorded for offline revocation matching
}

// CarriedTierBoundUnverified is the tier of a carried attestation whose subjects
// are digest-bound to the installed bytes but whose external signature is not
// yet verified (that is phase 2c).
const CarriedTierBoundUnverified = "bound-unverified"

// CarriedTierBuilderVerified is the tier of a carried attestation whose builder
// (DSSE) signature verified against a known, non-revoked key in the source's
// trust bundle, in addition to being digest-bound to the installed bytes (2c-1a).
const CarriedTierBuilderVerified = "builder-verified"

// CarriedTierVerifiedTransportOnly is the tier of a carried attestation that is
// digest-bound and publisher-transport-verified but conveys no verified builder
// identity: either a DSSE envelope whose builder signature could not be verified
// against a non-revoked bundle key (no bundle published, an unknown or revoked
// key id, a signature that fails, or a structurally-invalid envelope), or a
// recognized but unsigned SBOM document (raw SPDX/CycloneDX, phase 2c-2). It is
// honest weaker-than-verified state (D-P6); refusing an install on this tier is a
// policy decision (phase 2d), not something the verifiers do.
const CarriedTierVerifiedTransportOnly = "verified-transport-only"

// CarriedTierVerifiedOffline is the tier of a carried sigstore bundle whose full
// chain (Fulcio cert to the mirrored root, Rekor inclusion proof + SET, inner DSSE
// signature) verified OFFLINE against the source's mirrored SigstoreRoot. The
// Fulcio identity is recorded (CertificateIdentity/CertificateIssuer) but not
// gated — the SAN/issuer allow-list is phase 2d. Distinct from builder-verified
// (long-lived builder key) per spec §5.4/D-P6.
const CarriedTierVerifiedOffline = "verified-offline"

// ManifestEntry is one resolved package in the manifest.
type ManifestEntry struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	ContentHash string `json:"content_hash"`
	// Platform is the <os>/<arch>[/<variant>] the installed artifact was
	// published for, recorded at apply. Empty means the artifact is
	// platform-agnostic ("any"); generations written before the field existed
	// read back as agnostic. omitempty keeps their canonical bytes unchanged.
	Platform      string            `json:"platform,omitempty"`
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
