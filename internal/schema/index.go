package schema

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
)

//go:embed jsonschema/index-v3.json
var indexSchemaV3 []byte

// indexSchemaKind and indexSchemaVersion name the only index format this
// binary reads: polypkg.index/v3.
const (
	indexSchemaKind    = "polypkg.index"
	indexSchemaVersion = 3

	// IndexSchemaID is the "schema" value of the index this binary reads and
	// repo build writes: indexSchemaKind + "/v" + indexSchemaVersion. Go cannot
	// format an integer into a constant, so it is spelled out; a test keeps
	// it equal to the pair.
	IndexSchemaID = "polypkg.index/v3"
)

// AttestationRef points at one signed attestation for an index entry. Living
// inside the signed index makes attestations strip-resistant: removing one
// invalidates the index signature.
//
// Kind/Format/SubjectScope/SubjectDigests carry external provenance:
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
	Platform     string           `json:"platform,omitempty"` // <os>/<arch>[/<variant>]; "" = platform-agnostic
	ContentHash  string           `json:"content_hash"`
	Artifact     string           `json:"artifact"`
	Revision     int              `json:"revision,omitempty"` // informational rebuild ordinal
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
	Schema   string                  `json:"schema"`  // polypkg.index/v3
	Expires  string                  `json:"expires"` // RFC3339; consumer rejects stale
	Packages map[string][]IndexEntry `json:"packages"`
}

// OlderIndexError reports a source index in an earlier polypkg.index format
// than this binary reads. There is no dual-read: the repository has to be
// rebuilt by a current polypkg, which only its operator can do.
type OlderIndexError struct {
	// Found is the document's schema identifier, e.g. "polypkg.index/v2".
	Found string
}

func (e *OlderIndexError) Error() string {
	return fmt.Sprintf("the repository index is %s, which an older polypkg built; this polypkg reads only %s",
		e.Found, IndexSchemaID)
}

// ParseIndex reads a JSON source index, rejects unknown fields, and validates
// it against the embedded v3 JSON Schema. An index from a newer polypkg is a
// *NewerSchemaError and one from an older polypkg an *OlderIndexError, both
// reported before strict decoding, whose unknown-field error would not say why.
func ParseIndex(r io.Reader) (*Index, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read index: %w", err)
	}
	if err := checkNotNewer(data, indexSchemaV3); err != nil {
		return nil, err
	}
	if err := checkIndexNotOlder(data); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var idx Index
	if err := dec.Decode(&idx); err != nil {
		return nil, fmt.Errorf("decode index: %w", err)
	}

	if err := validateAgainstSchema(data, indexSchemaV3, "index-v3.json"); err != nil {
		return nil, err
	}
	return &idx, nil
}

// checkIndexNotOlder returns an *OlderIndexError when data declares a
// polypkg.index version below the one this binary reads. Like checkNotNewer it
// never accepts a document: anything it cannot interpret returns nil and is
// left to strict validation.
func checkIndexNotOlder(data []byte) error {
	var doc struct {
		Schema any `json:"schema"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	found, ok := doc.Schema.(string)
	if !ok {
		return nil
	}
	kind, version, ok := parseSchemaID(found)
	if !ok || kind != indexSchemaKind || version >= indexSchemaVersion {
		return nil
	}
	return &OlderIndexError{Found: found}
}
