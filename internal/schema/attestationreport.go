package schema

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

//go:embed jsonschema/attestation-report-v1.json
var attestationReportSchemaV1 []byte

// AttestationReportSchemaV1 is the schema id of a polypkg.attestation-report/v1
// document.
const AttestationReportSchemaV1 = "polypkg.attestation-report/v1"

// AttestationReport (polypkg.attestation-report/v1) is a deterministic audit
// document: for every installed package across all retained generations, it
// aggregates the provenance evidence already recorded and individually anchored
// at install time (AttestationState + CarriedBinding). It is a FAITHFUL
// AGGREGATION, not operator-signed — trust derives from the upstream signatures
// each recorded hash verifies against, not from any consumer signature (spec
// §10.9 E-7). An optional operator counter-signature (--sign) is deferred.
type AttestationReport struct {
	Schema        string            `json:"schema"`
	GeneratedFrom ReportSource      `json:"generated_from"`
	Packages      []PackageEvidence `json:"packages"`
}

// ReportSource records what the report was generated from: the scope and the
// sorted set of retained generation ids included. No wall-clock field — the
// report must be reproducible purely from on-disk state.
type ReportSource struct {
	Scope       string `json:"scope"`
	Generations []int  `json:"generations"`
}

// PackageEvidence is one installed package's recorded provenance, keyed to the
// generation it appears in. InstalledAt is the generation manifest's recorded
// ProducedBy.Timestamp (never a query-time clock). The attestation fields mirror
// AttestationState verbatim; an entry with no recorded AttestationState carries
// only the identity fields.
type PackageEvidence struct {
	Name            string           `json:"name"`
	Version         string           `json:"version"`
	Generation      int              `json:"generation"`
	ContentHash     string           `json:"content_hash"`
	InstalledAt     time.Time        `json:"installed_at"`
	Status          string           `json:"status,omitempty"`
	PredicateTypes  []string         `json:"predicate_types,omitempty"`
	AttestationHash string           `json:"attestation_hash,omitempty"`
	PolicyAtInstall string           `json:"policy_at_install,omitempty"`
	GateDisabled    bool             `json:"gate_disabled,omitempty"`
	CarriedBindings []CarriedBinding `json:"carried_bindings,omitempty"`
}

// ParseAttestationReport strictly decodes and schema-validates an attestation
// report. It exists for round-trip tests and a future verify/--sign path; the
// CLI builds the struct in memory rather than parsing one.
func ParseAttestationReport(r io.Reader) (*AttestationReport, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read attestation report: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m AttestationReport
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode attestation report: %w", err)
	}
	if err := validateAgainstSchema(data, attestationReportSchemaV1, "attestation-report-v1.json"); err != nil {
		return nil, err
	}
	return &m, nil
}
