package attest_test

import (
	"encoding/base64"
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// dsseWrap builds a minimal DSSE envelope carrying an in-toto Statement payload.
func dsseWrap(statement []byte) []byte {
	env := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(statement),
		"signatures":  []map[string]string{{"keyid": "k", "sig": "AA=="}},
	}
	b, _ := json.Marshal(env)
	return b
}

func slsaStatement(predicateType string) []byte {
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"name": "hello", "digest": map[string]string{"sha256": "cafe"}}},
		"predicateType": predicateType,
		"predicate":     map[string]any{},
	}
	b, _ := json.Marshal(st)
	return b
}

var _ = Describe("ExtractCarriedSubjects", func() {
	It("extracts subjects from a DSSE-wrapped SLSA statement and classifies the format", func() {
		env := dsseWrap(slsaStatement("https://slsa.dev/provenance/v1"))
		predicateType, format, subjects, err := attest.ExtractCarriedSubjects(env)
		Expect(err).NotTo(HaveOccurred())
		Expect(predicateType).To(Equal("https://slsa.dev/provenance/v1"))
		Expect(format).To(Equal(schema.FormatSLSAProvenance))
		Expect(subjects).To(HaveLen(1))
		Expect(subjects[0].Digest["sha256"]).To(Equal("cafe"))
	})

	It("extracts subjects from a bare in-toto Statement (no DSSE envelope)", func() {
		_, format, subjects, err := attest.ExtractCarriedSubjects(slsaStatement("https://slsa.dev/provenance/v0.2"))
		Expect(err).NotTo(HaveOccurred())
		Expect(format).To(Equal(schema.FormatSLSAProvenance))
		Expect(subjects).To(HaveLen(1))
	})

	It("classifies SPDX and CycloneDX in-toto predicate types", func() {
		_, f1, _, err := attest.ExtractCarriedSubjects(slsaStatement("https://spdx.dev/Document"))
		Expect(err).NotTo(HaveOccurred())
		Expect(f1).To(Equal(schema.FormatSPDX))
		_, f2, _, err := attest.ExtractCarriedSubjects(slsaStatement("https://cyclonedx.org/bom"))
		Expect(err).NotTo(HaveOccurred())
		Expect(f2).To(Equal(schema.FormatCycloneDX))
	})

	It("classifies an unknown predicate type as generic in-toto", func() {
		_, format, _, err := attest.ExtractCarriedSubjects(slsaStatement("https://example.com/custom/v1"))
		Expect(err).NotTo(HaveOccurred())
		Expect(format).To(Equal(schema.FormatInTotoGeneric))
	})

	It("rejects a DSSE envelope whose payloadType is not in-toto", func() {
		env := map[string]any{"payloadType": "application/vnd.other", "payload": base64.StdEncoding.EncodeToString([]byte("{}")), "signatures": []any{}}
		b, _ := json.Marshal(env)
		_, _, _, err := attest.ExtractCarriedSubjects(b)
		Expect(err).To(MatchError(ContainSubstring("payloadType")))
	})

	It("rejects a DSSE envelope with an undecodable base64 payload", func() {
		env := map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": "!!!not-base64!!!", "signatures": []any{}}
		b, _ := json.Marshal(env)
		_, _, _, err := attest.ExtractCarriedSubjects(b)
		Expect(err).To(MatchError(ContainSubstring("payload")))
	})

	It("rejects an unrecognized envelope (neither DSSE nor a Statement)", func() {
		_, _, _, err := attest.ExtractCarriedSubjects([]byte(`{"random":"json"}`))
		Expect(err).To(MatchError(ContainSubstring("unrecognized")))
	})

	It("rejects a statement whose subjects carry no digest (via ParseStatement)", func() {
		bad := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"a","digest":{}}],"predicateType":"x","predicate":{}}`)
		_, _, _, err := attest.ExtractCarriedSubjects(bad)
		Expect(err).To(HaveOccurred())
	})
})
