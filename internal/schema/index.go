package schema

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
)

//go:embed jsonschema/index-v2.json
var indexSchemaV2 []byte

// AttestationRef points at one signed attestation for an index entry. Living
// inside the signed index makes attestations strip-resistant: removing one
// invalidates the index signature (D7).
//
// Kind/Format/SubjectScope/SubjectDigests carry external provenance (phase 2b):
// they are optional and absent on the pre-carriage native-jcs SARIF ref, which
// is treated as Kind==KindNativeJCS by default.
type AttestationRef struct {
	PredicateType  string            `json:"predicate_type"`
	Artifact       string            `json:"artifact"`                  // pool/<attblake3>.att.json
	ContentHash    string            `json:"content_hash"`              // blake3:… of the att.json bytes
	Kind           string            `json:"kind,omitempty"`            // KindNativeJCS | KindCarriedOpaque (absent ⇒ native-jcs)
	Format         string            `json:"format,omitempty"`          // Format* — the predicate family
	SubjectScope   string            `json:"subject_scope,omitempty"`   // "artifact" | "content:<path>" (advisory; binding selects by digest)
	SubjectDigests map[string]string `json:"subject_digests,omitempty"` // advisory algo→bare-hex; authoritative digests come from the verified payload
}

// Attestation kinds: how the stored envelope is represented.
const (
	// KindNativeJCS is a polypkg-authored in-toto Statement, JCS-canonicalized
	// and minisign-signed (the pre-carriage default).
	KindNativeJCS = "native-jcs"
	// KindCarriedOpaque is an external builder's envelope stored verbatim
	// (never re-canonicalized) with a publisher transport signature.
	KindCarriedOpaque = "carried-opaque"
)

// Attestation formats: the predicate family a ref carries. This is the closed
// wire vocabulary the index schema enforces; verification of each is phased in
// later (2c).
const (
	FormatPolypkgSARIF       = "polypkg-sarif"
	FormatPolypkgLink        = "polypkg-link"
	FormatSLSAProvenance     = "slsa-provenance"
	FormatSPDX               = "spdx"
	FormatCycloneDX          = "cyclonedx"
	FormatInTotoGeneric      = "in-toto-generic"
	FormatInTotoUnclassified = "in-toto-unclassified"
	FormatSigstoreBundle     = "sigstore-bundle"
)

// IndexEntry is one available package version in a source index.
type IndexEntry struct {
	Version      string           `json:"version"`
	ContentHash  string           `json:"content_hash"`
	Artifact     string           `json:"artifact"`
	Revision     int              `json:"revision,omitempty"` // informational rebuild ordinal (D10)
	Attestations []AttestationRef `json:"attestations,omitempty"`
	Depends      []Relation       `json:"depends,omitempty"`
	Recommends   []Relation       `json:"recommends,omitempty"`
	Suggests     []Relation       `json:"suggests,omitempty"`
	Provides     []Relation       `json:"provides,omitempty"`
	Conflicts    []Relation       `json:"conflicts,omitempty"`
	Obsoletes    []Relation       `json:"obsoletes,omitempty"`
}

// Index is a source's published catalog of available packages.
type Index struct {
	Schema   string                  `json:"schema"`  // polypkg.index/v2
	Expires  string                  `json:"expires"` // RFC3339; consumer rejects stale (D13)
	Packages map[string][]IndexEntry `json:"packages"`
}

// ParseIndex reads a JSON source index, rejects unknown fields, and validates
// it against the embedded v2 JSON Schema.
func ParseIndex(r io.Reader) (*Index, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read index: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var idx Index
	if err := dec.Decode(&idx); err != nil {
		return nil, fmt.Errorf("decode index: %w", err)
	}

	if err := validateAgainstSchema(data, indexSchemaV2, "index-v2.json"); err != nil {
		return nil, err
	}
	return &idx, nil
}
