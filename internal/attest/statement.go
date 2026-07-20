// Package attest assembles the predicate-agnostic in-toto Statement that binds
// a lint (SARIF) predicate to a package's BLAKE3 digest. Phase B produces the
// unsigned preview; Phase C signs the identical bytes.
package attest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gowebpki/jcs"
)

// PredicateTypeSARIF is polypkg's custom predicate URI. There is no official
// in-toto SARIF predicate; SARIF is embedded under this polypkg-controlled type.
const PredicateTypeSARIF = "https://polypkg.dev/attestation/sarif/v1"

// statementType is the in-toto Statement v1 layout identifier. Verified against
// the in-toto/attestation spec (spec/v1/statement.md): the Statement's `_type`
// field is exactly "https://in-toto.io/Statement/v1".
const statementType = "https://in-toto.io/Statement/v1"

// Subject binds a named artifact to a digest set (algorithm -> hex).
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Statement is an in-toto Statement carrying an arbitrary predicate.
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// AssembleStatement builds a SARIF-predicate Statement. digestHex is the BARE
// blake3 hex (no "blake3:" prefix); sarif is the canonical SARIF document.
func AssembleStatement(artifactName, digestHex string, sarif json.RawMessage) Statement {
	return Statement{
		Type:          statementType,
		Subject:       []Subject{{Name: artifactName, Digest: map[string]string{"blake3": digestHex}}},
		PredicateType: PredicateTypeSARIF,
		Predicate:     sarif,
	}
}

// CanonicalJSON returns the JCS-canonicalized Statement bytes — the exact bytes
// the publisher signs, so the author's preview matches the signed attestation.
func (s Statement) CanonicalJSON() ([]byte, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

// ParseStatement strictly decodes and validates an in-toto Statement: correct
// _type, at least one subject carrying at least one digest (any algorithm — a
// carried SLSA statement digests subjects by sha256, not blake3), and a
// non-empty predicateType. Unknown fields are rejected — the consumer must not
// accept a statement shape it does not understand. Binding to a specific
// artifact/content digest is the caller's job (it selects the matching subject
// by digest), not ParseStatement's.
func ParseStatement(data []byte) (Statement, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var st Statement
	if err := dec.Decode(&st); err != nil {
		return Statement{}, fmt.Errorf("decode statement: %w", err)
	}
	if st.Type != statementType {
		return Statement{}, fmt.Errorf("statement _type %q, want %q", st.Type, statementType)
	}
	if len(st.Subject) == 0 {
		return Statement{}, errors.New("statement has no subject")
	}
	hasDigest := false
	for _, s := range st.Subject {
		if len(s.Digest) > 0 {
			hasDigest = true
			break
		}
	}
	if !hasDigest {
		return Statement{}, errors.New("statement has no subject digest")
	}
	if st.PredicateType == "" {
		return Statement{}, errors.New("statement has no predicateType")
	}
	return st, nil
}
