package attest_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"time"

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

	It("classifies an unknown predicate type as in-toto-unclassified", func() {
		_, format, _, err := attest.ExtractCarriedSubjects(slsaStatement("https://example.com/custom/v1"))
		Expect(err).NotTo(HaveOccurred())
		Expect(format).To(Equal(schema.FormatInTotoUnclassified))
	})

	It("classifies an allow-listed generic predicate as in-toto-generic", func() {
		_, format, _, err := attest.ExtractCarriedSubjects(slsaStatement("https://in-toto.io/attestation/link/v0.3"))
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

var _ = Describe("InspectCarried SLSA predicate interpretation", func() {
	build := func(predicateType string, predicate map[string]any) []byte {
		st := map[string]any{
			"_type":         "https://in-toto.io/Statement/v1",
			"subject":       []map[string]any{{"name": "a", "digest": map[string]string{"sha256": "ab"}}},
			"predicateType": predicateType,
			"predicate":     predicate,
		}
		b, _ := json.Marshal(st)
		return b
	}

	It("extracts builder id and finishedOn from SLSA v1.0", func() {
		env := build("https://slsa.dev/provenance/v1", map[string]any{
			"runDetails": map[string]any{
				"builder":  map[string]any{"id": "https://ci/b"},
				"metadata": map[string]any{"startedOn": "2024-01-01T00:00:00Z", "finishedOn": "2024-06-01T00:00:00Z"},
			},
		})
		info, err := attest.InspectCarried(env)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Format).To(Equal(schema.FormatSLSAProvenance))
		Expect(info.SLSABuilderID).To(Equal("https://ci/b"))
		Expect(info.BuildTimeKnown).To(BeTrue())
		Expect(info.BuildTime).To(Equal(time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)))
	})

	It("falls back to startedOn when finishedOn is absent (v1.0)", func() {
		env := build("https://slsa.dev/provenance/v1", map[string]any{
			"runDetails": map[string]any{"metadata": map[string]any{"startedOn": "2024-01-01T00:00:00Z"}},
		})
		info, err := attest.InspectCarried(env)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.BuildTimeKnown).To(BeTrue())
		Expect(info.BuildTime).To(Equal(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)))
	})

	It("extracts builder id and buildFinishedOn from SLSA v0.2", func() {
		env := build("https://slsa.dev/provenance/v0.2", map[string]any{
			"builder":  map[string]any{"id": "https://ci/v02"},
			"metadata": map[string]any{"buildFinishedOn": "2023-03-03T00:00:00Z"},
		})
		info, err := attest.InspectCarried(env)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Format).To(Equal(schema.FormatSLSAProvenance))
		Expect(info.SLSABuilderID).To(Equal("https://ci/v02"))
		Expect(info.BuildTimeKnown).To(BeTrue())
		Expect(info.BuildTime).To(Equal(time.Date(2023, 3, 3, 0, 0, 0, 0, time.UTC)))
	})

	It("reports no timestamp and no builder for a SLSA statement without metadata (F1)", func() {
		env := build("https://slsa.dev/provenance/v1", map[string]any{})
		info, err := attest.InspectCarried(env)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.SLSABuilderID).To(BeEmpty())
		Expect(info.BuildTimeKnown).To(BeFalse())
	})

	It("reports no builder id or timestamp for a non-SLSA predicate", func() {
		env := build("https://in-toto.io/attestation/link/v0.3", map[string]any{})
		info, err := attest.InspectCarried(env)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Format).To(Equal(schema.FormatInTotoGeneric))
		Expect(info.SLSABuilderID).To(BeEmpty())
		Expect(info.BuildTimeKnown).To(BeFalse())
	})
})

var _ = Describe("InspectCarried raw SBOM recognition", func() {
	rawSPDX := func(fileName, algo, value string) []byte {
		doc := map[string]any{
			"spdxVersion": "SPDX-2.3",
			"SPDXID":      "SPDXRef-DOCUMENT",
			"name":        "hello-sbom",
			"files": []map[string]any{{
				"fileName": fileName,
				"SPDXID":   "SPDXRef-File-hello",
				"checksums": []map[string]any{
					{"algorithm": "SHA1", "checksumValue": "0000000000000000000000000000000000000000"},
					{"algorithm": algo, "checksumValue": value},
				},
			}},
		}
		b, _ := json.Marshal(doc)
		return b
	}
	rawCycloneDX := func(name, algo, value string) []byte {
		doc := map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"metadata": map[string]any{
				"component": map[string]any{
					"type":   "application",
					"name":   name,
					"hashes": []map[string]any{{"alg": algo, "content": value}},
				},
			},
		}
		b, _ := json.Marshal(doc)
		return b
	}

	It("recognizes a raw SPDX document and synthesizes a bindable subject (SHA256 kept, SHA1 dropped)", func() {
		info, err := attest.InspectCarried(rawSPDX("bin/hello", "SHA256", "abc123"))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Format).To(Equal(schema.FormatSPDX))
		Expect(info.PredicateType).To(Equal("https://spdx.dev/Document"))
		Expect(info.Subjects).To(HaveLen(1))
		Expect(info.Subjects[0].Digest).To(HaveKeyWithValue("sha256", "abc123"))
		Expect(info.Subjects[0].Digest).NotTo(HaveKey("sha1")) // forbidden algo dropped, not rejected
	})

	It("recognizes a raw CycloneDX BOM and normalizes SHA-256 to sha256", func() {
		info, err := attest.InspectCarried(rawCycloneDX("hello", "SHA-256", "deadbeef"))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Format).To(Equal(schema.FormatCycloneDX))
		Expect(info.PredicateType).To(Equal("https://cyclonedx.org/bom"))
		Expect(info.Subjects).To(HaveLen(1))
		Expect(info.Subjects[0].Digest).To(HaveKeyWithValue("sha256", "deadbeef"))
	})

	It("normalizes the SPDX SHA512 dialect", func() {
		info, err := attest.InspectCarried(rawSPDX("bin/hello", "SHA512", "ff00"))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Subjects[0].Digest).To(HaveKeyWithValue("sha512", "ff00"))
	})

	It("synthesizes a subject from a raw SPDX packages[] entry", func() {
		doc := map[string]any{
			"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "pkg-sbom",
			"packages": []map[string]any{{
				"name": "curl", "SPDXID": "SPDXRef-Package-curl",
				"checksums": []map[string]any{{"algorithm": "SHA256", "checksumValue": "pkg256"}},
			}},
		}
		b, _ := json.Marshal(doc)
		info, err := attest.InspectCarried(b)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Format).To(Equal(schema.FormatSPDX))
		Expect(info.Subjects).To(HaveLen(1))
		Expect(info.Subjects[0].Digest).To(HaveKeyWithValue("sha256", "pkg256"))
	})

	It("collects hashes from nested CycloneDX components", func() {
		doc := map[string]any{
			"bomFormat": "CycloneDX", "specVersion": "1.5",
			"components": []map[string]any{{
				"type": "library", "name": "outer",
				"components": []map[string]any{{
					"type": "library", "name": "inner",
					"hashes": []map[string]any{{"alg": "SHA-256", "content": "innerhash"}},
				}},
			}},
		}
		b, _ := json.Marshal(doc)
		info, err := attest.InspectCarried(b)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Subjects).To(ContainElement(HaveField("Digest", HaveKeyWithValue("sha256", "innerhash"))))
	})

	It("yields no bindable subject when a file offers only a forbidden algorithm", func() {
		doc := map[string]any{
			"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "s",
			"files": []map[string]any{{
				"fileName": "bin/hello", "SPDXID": "SPDXRef-File",
				"checksums": []map[string]any{{"algorithm": "SHA1", "checksumValue": "00"}},
			}},
		}
		b, _ := json.Marshal(doc)
		info, err := attest.InspectCarried(b)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Format).To(Equal(schema.FormatSPDX))
		Expect(info.Subjects).To(BeEmpty()) // sha1 dropped ⇒ empty digest set ⇒ subject omitted (binder will refuse)
	})

	It("still rejects a random JSON object that is neither DSSE, Statement, nor SBOM", func() {
		_, err := attest.InspectCarried([]byte(`{"random":"json"}`))
		Expect(err).To(MatchError(ContainSubstring("unrecognized")))
	})
})

var _ = Describe("InspectCarried sigstore bundle recognition", func() {
	It("recognizes a real dev.sigstore.bundle and extracts subjects + integrated time", func() {
		data, err := os.ReadFile("testdata/bundle-provenance.json")
		Expect(err).NotTo(HaveOccurred())
		info, err := attest.InspectCarried(data)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Format).To(Equal(schema.FormatSigstoreBundle))
		Expect(info.PredicateType).To(Equal("https://slsa.dev/provenance/v0.2"))
		Expect(info.Subjects).NotTo(BeEmpty())
		Expect(info.BuildTimeKnown).To(BeTrue())
		Expect(info.BuildTime).To(Equal(time.Date(2023, 4, 18, 17, 45, 12, 0, time.UTC)))
	})

	It("recognizes the v0.3 bundle GitHub artifact attestations publish", func() {
		data, err := os.ReadFile("testdata/github-bundle.json")
		Expect(err).NotTo(HaveOccurred())
		var probe struct {
			MediaType string `json:"mediaType"`
		}
		Expect(json.Unmarshal(data, &probe)).To(Succeed())
		Expect(probe.MediaType).To(Equal("application/vnd.dev.sigstore.bundle.v0.3+json"))

		info, err := attest.InspectCarried(data)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Format).To(Equal(schema.FormatSigstoreBundle))
		Expect(info.PredicateType).To(Equal("https://slsa.dev/provenance/v1"))
		asset, err := os.ReadFile("testdata/github-asset.bin")
		Expect(err).NotTo(HaveOccurred())
		sum := sha256.Sum256(asset)
		Expect(info.Subjects).To(HaveLen(1))
		Expect(info.Subjects[0].Digest).To(HaveKeyWithValue("sha256", hex.EncodeToString(sum[:])))
		Expect(info.BuildTimeKnown).To(BeTrue())
	})

	It("recognizes a bundle by verificationMaterial when mediaType is absent", func() {
		stmt := map[string]any{
			"_type":         "https://in-toto.io/Statement/v1",
			"subject":       []map[string]any{{"name": "a", "digest": map[string]string{"sha256": "ab"}}},
			"predicateType": "https://slsa.dev/provenance/v1",
			"predicate":     map[string]any{},
		}
		sb, _ := json.Marshal(stmt)
		b := map[string]any{
			"verificationMaterial": map[string]any{"tlogEntries": []map[string]any{{"integratedTime": "1700000000"}}},
			"dsseEnvelope": map[string]any{
				"payload":     base64.StdEncoding.EncodeToString(sb),
				"payloadType": "application/vnd.in-toto+json",
				"signatures":  []map[string]string{{"sig": "AA=="}},
			},
		}
		data, _ := json.Marshal(b)
		info, err := attest.InspectCarried(data)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Format).To(Equal(schema.FormatSigstoreBundle))
		Expect(info.Subjects).To(HaveLen(1))
		Expect(info.BuildTimeKnown).To(BeTrue())
		Expect(info.BuildTime).To(Equal(time.Unix(1700000000, 0).UTC()))
	})

	It("errors on a sigstore bundle with no dsse envelope (message-signature only)", func() {
		b := map[string]any{
			"mediaType":            "application/vnd.dev.sigstore.bundle.v0.3+json",
			"verificationMaterial": map[string]any{"tlogEntries": []map[string]any{{"integratedTime": "1700000000"}}},
			"messageSignature":     map[string]any{"messageDigest": map[string]any{"algorithm": "SHA2_256", "digest": "ab"}},
		}
		data, _ := json.Marshal(b)
		_, err := attest.InspectCarried(data)
		Expect(err).To(HaveOccurred())
	})

	It("decodes a URL-safe base64 dsse payload (proto3-JSON parity)", func() {
		// proto3 JSON accepts URL-safe base64 for bytes fields, and sigstore-go's
		// protojson parser (which the kernel uses to verify the same payload)
		// honours it; recognition must decode the identical bytes or a conformant
		// bundle would be wrongly refused. The subject name is a run of U+00FF so
		// the payload's URL-safe encoding is genuinely NOT valid standard base64.
		stmt := map[string]any{
			"_type":         "https://in-toto.io/Statement/v1",
			"subject":       []map[string]any{{"name": "ÿÿÿÿÿÿÿÿ", "digest": map[string]string{"sha256": "ab"}}},
			"predicateType": "https://slsa.dev/provenance/v1",
			"predicate":     map[string]any{},
		}
		sb, _ := json.Marshal(stmt)
		urlPayload := base64.URLEncoding.EncodeToString(sb)
		// Sanity: confirm this payload really is URL-safe-only, so the spec
		// genuinely exercises the URL-safe decode path (not the standard one).
		_, stdErr := base64.StdEncoding.DecodeString(urlPayload)
		Expect(stdErr).To(HaveOccurred())

		b := map[string]any{
			"mediaType":            "application/vnd.dev.sigstore.bundle.v0.3+json",
			"verificationMaterial": map[string]any{"tlogEntries": []map[string]any{{"integratedTime": "1700000000"}}},
			"dsseEnvelope": map[string]any{
				"payload":     urlPayload,
				"payloadType": "application/vnd.in-toto+json",
				"signatures":  []map[string]string{{"sig": "AA=="}},
			},
		}
		data, _ := json.Marshal(b)
		info, err := attest.InspectCarried(data)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Format).To(Equal(schema.FormatSigstoreBundle))
		Expect(info.Subjects).To(HaveLen(1))
	})

	It("does not treat a scalar verificationMaterial as a bundle", func() {
		// A top-level verificationMaterial that is not a JSON object (here a
		// string) does not make a document a sigstore bundle; recognition must
		// fall through to "unrecognized" rather than misroute into the sigstore
		// parser.
		data := []byte(`{"verificationMaterial": "not-an-object"}`)
		_, err := attest.InspectCarried(data)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unrecognized"))
	})
})
