package attest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// inTotoPayloadType is the DSSE payloadType for an in-toto Statement.
const inTotoPayloadType = "application/vnd.in-toto+json"

// ExtractCarriedSubjects shallow-parses a carried attestation envelope and
// returns the inner statement's predicateType, the detected polypkg format, and
// the in-toto subjects it covers. It accepts a DSSE envelope wrapping an in-toto
// Statement, or a bare in-toto Statement. It does NOT verify the DSSE/builder
// signature — that is a later phase; this only reads the subject set so the
// caller can bind those digests against the bytes polypkg actually packs. Raw
// SBOMs and sigstore bundles are not handled here (a later phase); an
// unrecognized envelope is an error.
func ExtractCarriedSubjects(data []byte) (predicateType, format string, subjects []Subject, err error) {
	// Probe for a DSSE envelope (payloadType + payload) vs a bare Statement
	// (_type). A permissive decode: envelopes carry extra fields we ignore.
	var probe struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Type        string `json:"_type"`
	}
	if jerr := json.Unmarshal(data, &probe); jerr != nil {
		return "", "", nil, fmt.Errorf("parse attestation envelope: %w", jerr)
	}

	var stmtBytes []byte
	switch {
	case probe.PayloadType != "" || probe.Payload != "":
		if probe.PayloadType != inTotoPayloadType {
			return "", "", nil, fmt.Errorf("carried DSSE payloadType %q is not %q", probe.PayloadType, inTotoPayloadType)
		}
		decoded, derr := base64.StdEncoding.DecodeString(probe.Payload)
		if derr != nil {
			return "", "", nil, fmt.Errorf("decode carried DSSE payload: %w", derr)
		}
		stmtBytes = decoded
	case probe.Type != "":
		stmtBytes = data
	default:
		return "", "", nil, errors.New("unrecognized attestation envelope: neither a DSSE envelope nor an in-toto Statement")
	}

	st, perr := ParseStatement(stmtBytes)
	if perr != nil {
		return "", "", nil, fmt.Errorf("parse carried statement: %w", perr)
	}
	return st.PredicateType, classifyFormat(st.PredicateType), st.Subject, nil
}

// classifyFormat maps an in-toto predicateType to the polypkg carriage format.
// SLSA provenance (any version), SPDX, and CycloneDX are recognized; anything
// else is generic in-toto.
func classifyFormat(predicateType string) string {
	switch {
	case strings.HasPrefix(predicateType, "https://slsa.dev/provenance/"):
		return schema.FormatSLSAProvenance
	case predicateType == "https://spdx.dev/Document":
		return schema.FormatSPDX
	case predicateType == "https://cyclonedx.org/bom":
		return schema.FormatCycloneDX
	default:
		return schema.FormatInTotoGeneric
	}
}
