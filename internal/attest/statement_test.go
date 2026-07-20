package attest_test

import (
	"encoding/json"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/attest"
)

func TestAttest(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "attest")
}

var _ = Describe("Statement", func() {
	It("assembles an in-toto Statement binding the SARIF predicate to the digest", func() {
		sarifBytes := []byte(`{"version":"2.1.0","runs":[]}`)
		st := attest.AssembleStatement("hello-1.0.0.tar.zst", "deadbeef", sarifBytes)
		Expect(st.Type).To(Equal("https://in-toto.io/Statement/v1"))
		Expect(st.PredicateType).To(Equal(attest.PredicateTypeSARIF))
		Expect(st.Subject).To(HaveLen(1))
		Expect(st.Subject[0].Name).To(Equal("hello-1.0.0.tar.zst"))
		Expect(st.Subject[0].Digest["blake3"]).To(Equal("deadbeef"))
		Expect([]byte(st.Predicate)).To(Equal(sarifBytes))
	})

	It("canonicalizes deterministically (JCS)", func() {
		st := attest.AssembleStatement("a", "ff", []byte(`{"b":1,"a":2}`))
		x, err := st.CanonicalJSON()
		Expect(err).ToNot(HaveOccurred())
		y, err := st.CanonicalJSON()
		Expect(err).ToNot(HaveOccurred())
		Expect(x).To(Equal(y))
	})

	It("emits JCS-canonical bytes with sorted keys", func() {
		st := attest.AssembleStatement("a", "ff", json.RawMessage(`{"b":1,"a":2}`))
		got, err := st.CanonicalJSON()
		Expect(err).ToNot(HaveOccurred())
		// JCS sorts object member names lexicographically at every level: the
		// predicate's {"b":1,"a":2} must serialize as {"a":2,"b":1}, and the
		// Statement's own keys sort too (_type before subject before ...).
		Expect(string(got)).To(Equal(
			`{"_type":"https://in-toto.io/Statement/v1",` +
				`"predicate":{"a":2,"b":1},` +
				`"predicateType":"https://polypkg.dev/attestation/sarif/v1",` +
				`"subject":[{"digest":{"blake3":"ff"},"name":"a"}]}`))
	})
})

var _ = Describe("ParseStatement", func() {
	It("round-trips Assemble -> Canonical -> Parse", func() {
		st := attest.AssembleStatement("hello-1.0.0.tar.zst", "deadbeef", json.RawMessage(`{"version":"2.1.0","runs":[]}`))
		b, err := st.CanonicalJSON()
		Expect(err).ToNot(HaveOccurred())
		got, err := attest.ParseStatement(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Type).To(Equal("https://in-toto.io/Statement/v1"))
		Expect(got.PredicateType).To(Equal(attest.PredicateTypeSARIF))
		Expect(got.Subject).To(HaveLen(1))
		Expect(got.Subject[0].Name).To(Equal("hello-1.0.0.tar.zst"))
		Expect(got.Subject[0].Digest["blake3"]).To(Equal("deadbeef"))
	})

	It("rejects a wrong _type", func() {
		_, err := attest.ParseStatement([]byte(
			`{"_type":"https://in-toto.io/Statement/v0.1",` +
				`"subject":[{"name":"a","digest":{"blake3":"ff"}}],` +
				`"predicateType":"x","predicate":{}}`))
		Expect(err).To(MatchError(ContainSubstring("_type")))
	})

	It("rejects a statement with no subject", func() {
		_, err := attest.ParseStatement([]byte(
			`{"_type":"https://in-toto.io/Statement/v1",` +
				`"subject":[],"predicateType":"x","predicate":{}}`))
		Expect(err).To(MatchError(ContainSubstring("no subject")))
	})

	It("accepts a subject whose only digest is sha256 (carried provenance)", func() {
		st, err := attest.ParseStatement([]byte(
			`{"_type":"https://in-toto.io/Statement/v1",` +
				`"subject":[{"name":"a","digest":{"sha256":"ff"}}],` +
				`"predicateType":"x","predicate":{}}`))
		Expect(err).NotTo(HaveOccurred())
		Expect(st.Subject[0].Digest["sha256"]).To(Equal("ff"))
	})

	It("rejects a subject with an empty digest set", func() {
		_, err := attest.ParseStatement([]byte(
			`{"_type":"https://in-toto.io/Statement/v1",` +
				`"subject":[{"name":"a","digest":{}}],` +
				`"predicateType":"x","predicate":{}}`))
		Expect(err).To(MatchError(ContainSubstring("no subject digest")))
	})

	It("rejects an empty predicateType", func() {
		_, err := attest.ParseStatement([]byte(
			`{"_type":"https://in-toto.io/Statement/v1",` +
				`"subject":[{"name":"a","digest":{"blake3":"ff"}}],` +
				`"predicateType":"","predicate":{}}`))
		Expect(err).To(MatchError(ContainSubstring("predicateType")))
	})

	It("rejects unknown fields", func() {
		_, err := attest.ParseStatement([]byte(
			`{"_type":"https://in-toto.io/Statement/v1",` +
				`"subject":[{"name":"a","digest":{"blake3":"ff"}}],` +
				`"predicateType":"x","predicate":{},"smuggled":true}`))
		Expect(err).To(MatchError(ContainSubstring("decode statement")))
	})
})
