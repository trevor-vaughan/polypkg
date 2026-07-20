package attest

import (
	"encoding/json"
	"fmt"
)

// PredicateTypePolypkgLink is the predicate URI for polypkg's own link
// attestation, which binds a shipped artifact to the material digests the
// carried external provenance covers (an explicit, publisher-signed
// material→artifact statement for audit).
const PredicateTypePolypkgLink = "https://polypkg.dev/attestation/link/v1"

// LinkMaterial is one covered target the carried provenance describes: a scope
// label ("artifact" or "content:<path>") and the digest set polypkg bound.
type LinkMaterial struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// AssembleLinkStatement builds a native-jcs polypkg-link Statement whose subject
// is the shipped artifact (blake3) and whose predicate lists the materials the
// carried provenance covers. artifactBlake3Hex is BARE blake3 hex (no prefix).
func AssembleLinkStatement(artifactName, artifactBlake3Hex string, materials []LinkMaterial) (Statement, error) {
	pred, err := json.Marshal(struct {
		Materials []LinkMaterial `json:"materials"`
	}{Materials: materials})
	if err != nil {
		return Statement{}, fmt.Errorf("marshal link predicate: %w", err)
	}
	return Statement{
		Type:          statementType,
		Subject:       []Subject{{Name: artifactName, Digest: map[string]string{"blake3": artifactBlake3Hex}}},
		PredicateType: PredicateTypePolypkgLink,
		Predicate:     json.RawMessage(pred),
	}, nil
}
