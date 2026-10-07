package resolver

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("attestation ref threading", func() {
	It("carries an index entry's attestation refs through Candidate into Resolved", func() {
		ref := schema.AttestationRef{
			PredicateType: "https://polypkg.dev/attestation/sarif/v1",
			Artifact:      "pool/aa11.att.json",
			ContentHash:   "blake3:aa11",
		}
		idx := &schema.Index{
			Schema:  "polypkg.index/v3",
			Expires: "2099-01-01T00:00:00Z",
			Packages: map[string][]schema.IndexEntry{
				"a": {{
					Version: "1.0.0", ContentHash: "blake3:a1", Artifact: "pool/a1.tar.zst",
					Attestations: []schema.AttestationRef{ref},
				}},
			},
		}
		cat, err := BuildCatalog(idx, "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		out, err := Resolve([]Requirement{{Name: "a"}}, cat)
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(HaveLen(1))
		Expect(out[0].Attestations).To(Equal([]schema.AttestationRef{ref}))
	})

	It("leaves Attestations empty for an unattested entry", func() {
		cat, err := BuildCatalog(idx(), "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		out, err := Resolve([]Requirement{{Name: "a"}}, cat)
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(HaveLen(1))
		Expect(out[0].Attestations).To(BeEmpty())
	})
})
