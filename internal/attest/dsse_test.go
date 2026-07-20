package attest_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/attest"
)

// pae builds the DSSE Pre-Authentication Encoding independently of the
// production code, so a bug in attest's own pae() is caught rather than mirrored.
// secure-systems-lab/dsse protocol.md:
//
//	"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
func pae(payloadType string, body []byte) []byte {
	out := []byte("DSSEv1 ")
	out = append(out, []byte(strconv.Itoa(len(payloadType)))...)
	out = append(out, ' ')
	out = append(out, []byte(payloadType)...)
	out = append(out, ' ')
	out = append(out, []byte(strconv.Itoa(len(body)))...)
	out = append(out, ' ')
	out = append(out, body...)
	return out
}

const inToto = "application/vnd.in-toto+json"

// inTotoStatement is a minimal valid in-toto Statement body (any predicate).
func inTotoStatement() []byte {
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"name": "a", "digest": map[string]string{"sha256": "ab"}}},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate":     map[string]any{},
	}
	b, _ := json.Marshal(st)
	return b
}

// signedEnvelope wraps body in a DSSE envelope with one signature by priv over
// PAE(inToto, body), labelled keyID.
func signedEnvelope(keyID string, priv ed25519.PrivateKey, body []byte) []byte {
	sig := ed25519.Sign(priv, pae(inToto, body))
	env := map[string]any{
		"payloadType": inToto,
		"payload":     base64.StdEncoding.EncodeToString(body),
		"signatures":  []map[string]string{{"keyid": keyID, "sig": base64.StdEncoding.EncodeToString(sig)}},
	}
	b, _ := json.Marshal(env)
	return b
}

var _ = Describe("VerifyBuilderSignature", func() {
	var (
		pub    ed25519.PublicKey
		priv   ed25519.PrivateKey
		lookup attest.KeyLookup
		none   = func(string) bool { return false }
	)
	BeforeEach(func() {
		var err error
		pub, priv, err = ed25519.GenerateKey(nil)
		Expect(err).NotTo(HaveOccurred())
		lookup = func(id string) (ed25519.PublicKey, bool) {
			if id == "builder-a" {
				return pub, true
			}
			return nil, false
		}
	})

	It("verifies a well-formed envelope signed by a known key", func() {
		env := signedEnvelope("builder-a", priv, inTotoStatement())
		tier, keyID, err := attest.VerifyBuilderSignature(env, lookup, none)
		Expect(err).NotTo(HaveOccurred())
		Expect(tier).To(Equal(attest.BuilderSigVerified))
		Expect(keyID).To(Equal("builder-a"))
	})

	It("does not verify when the signing key is unknown to the bundle", func() {
		env := signedEnvelope("builder-x", priv, inTotoStatement()) // keyid not in lookup
		tier, _, err := attest.VerifyBuilderSignature(env, lookup, none)
		Expect(err).NotTo(HaveOccurred())
		Expect(tier).To(Equal(attest.BuilderSigTransportOnly))
	})

	It("does not verify a tampered payload (signature over the original body fails)", func() {
		env := signedEnvelope("builder-a", priv, inTotoStatement())
		var m map[string]any
		Expect(json.Unmarshal(env, &m)).To(Succeed())
		m["payload"] = base64.StdEncoding.EncodeToString([]byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"a","digest":{"sha256":"cd"}}],"predicateType":"x","predicate":{}}`))
		tampered, _ := json.Marshal(m)
		tier, _, err := attest.VerifyBuilderSignature(tampered, lookup, none)
		Expect(err).NotTo(HaveOccurred())
		Expect(tier).To(Equal(attest.BuilderSigTransportOnly))
	})

	It("skips a signature naming a revoked key (downgrade, not verified)", func() {
		env := signedEnvelope("builder-a", priv, inTotoStatement())
		revoked := func(id string) bool { return id == "builder-a" }
		tier, _, err := attest.VerifyBuilderSignature(env, lookup, revoked)
		Expect(err).NotTo(HaveOccurred())
		Expect(tier).To(Equal(attest.BuilderSigTransportOnly))
	})

	It("verifies when one of several signatures is from a known key (>=1-of-N)", func() {
		body := inTotoStatement()
		other, _, err := ed25519.GenerateKey(nil)
		_ = other
		Expect(err).NotTo(HaveOccurred())
		goodSig := ed25519.Sign(priv, pae(inToto, body))
		env := map[string]any{
			"payloadType": inToto,
			"payload":     base64.StdEncoding.EncodeToString(body),
			"signatures": []map[string]string{
				{"keyid": "unknown", "sig": base64.StdEncoding.EncodeToString([]byte("garbage-but-valid-b64=="))},
				{"keyid": "builder-a", "sig": base64.StdEncoding.EncodeToString(goodSig)},
			},
		}
		raw, _ := json.Marshal(env)
		tier, keyID, verr := attest.VerifyBuilderSignature(raw, lookup, none)
		Expect(verr).NotTo(HaveOccurred())
		Expect(tier).To(Equal(attest.BuilderSigVerified))
		Expect(keyID).To(Equal("builder-a"))
	})

	It("skips an undecodable signature block and still verifies a good one (no third-party downgrade)", func() {
		body := inTotoStatement()
		goodSig := ed25519.Sign(priv, pae(inToto, body))
		// A garbage, non-base64 block naming the SAME known key, prepended before
		// the real signature — an adversary must not be able to veto the good sig.
		raw := []byte(`{"payloadType":"` + inToto + `","payload":"` +
			base64.StdEncoding.EncodeToString(body) +
			`","signatures":[{"keyid":"builder-a","sig":"@@@not-base64@@@"},{"keyid":"builder-a","sig":"` +
			base64.StdEncoding.EncodeToString(goodSig) + `"}]}`)
		tier, keyID, err := attest.VerifyBuilderSignature(raw, lookup, none)
		Expect(err).NotTo(HaveOccurred())
		Expect(tier).To(Equal(attest.BuilderSigVerified))
		Expect(keyID).To(Equal("builder-a"))
	})

	It("rejects an envelope with duplicate JSON keys (G10 parser-differential)", func() {
		body := inTotoStatement()
		sig := ed25519.Sign(priv, pae(inToto, body))
		raw := []byte(`{"payloadType":"` + inToto + `","payload":"` +
			base64.StdEncoding.EncodeToString(body) + `","payload":"AAAA","signatures":[{"keyid":"builder-a","sig":"` +
			base64.StdEncoding.EncodeToString(sig) + `"}]}`)
		tier, _, err := attest.VerifyBuilderSignature(raw, lookup, none)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("duplicate"))
		Expect(tier).NotTo(Equal(attest.BuilderSigVerified))
	})

	It("rejects a non-in-toto payloadType", func() {
		body := inTotoStatement()
		sig := ed25519.Sign(priv, pae("application/vnd.other+json", body))
		env := map[string]any{
			"payloadType": "application/vnd.other+json",
			"payload":     base64.StdEncoding.EncodeToString(body),
			"signatures":  []map[string]string{{"keyid": "builder-a", "sig": base64.StdEncoding.EncodeToString(sig)}},
		}
		raw, _ := json.Marshal(env)
		tier, _, err := attest.VerifyBuilderSignature(raw, lookup, none)
		Expect(err).To(HaveOccurred())
		Expect(tier).NotTo(Equal(attest.BuilderSigVerified))
	})

	It("classifies a bare in-toto Statement as not-DSSE (no builder signature)", func() {
		tier, _, err := attest.VerifyBuilderSignature(inTotoStatement(), lookup, none)
		Expect(err).NotTo(HaveOccurred())
		Expect(tier).To(Equal(attest.BuilderSigNotDSSE))
	})
})
