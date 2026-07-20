package schema

import (
	"encoding/json"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("AttestationReport", func() {
	valid := func() AttestationReport {
		return AttestationReport{
			Schema:        AttestationReportSchemaV1,
			GeneratedFrom: ReportSource{Scope: "user", Generations: []int{1, 2}},
			Packages: []PackageEvidence{{
				Name:            "hello",
				Version:         "1.2.0",
				Generation:      2,
				ContentHash:     "blake3:abc",
				InstalledAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				Status:          "verified",
				PredicateTypes:  []string{"https://slsa.dev/provenance/v1"},
				PolicyAtInstall: "warn",
				CarriedBindings: []CarriedBinding{{
					PredicateType:  "https://slsa.dev/provenance/v1",
					Format:         "slsa-provenance",
					SubjectScope:   "artifact",
					Tier:           "builder-verified",
					VerifyingKeyID: "builder-a",
				}},
			}},
		}
	}

	It("round-trips a valid report through Parse", func() {
		b, err := json.Marshal(valid())
		Expect(err).NotTo(HaveOccurred())
		got, err := ParseAttestationReport(strings.NewReader(string(b)))
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Schema).To(Equal(AttestationReportSchemaV1))
		Expect(got.GeneratedFrom.Scope).To(Equal("user"))
		Expect(got.GeneratedFrom.Generations).To(Equal([]int{1, 2}))
		Expect(got.Packages).To(HaveLen(1))
		Expect(got.Packages[0].Name).To(Equal("hello"))
		Expect(got.Packages[0].CarriedBindings[0].Tier).To(Equal("builder-verified"))
	})

	It("accepts an empty report (no generations, no packages)", func() {
		src := `{"schema":"polypkg.attestation-report/v1","generated_from":{"scope":"user","generations":[]},"packages":[]}`
		_, err := ParseAttestationReport(strings.NewReader(src))
		Expect(err).NotTo(HaveOccurred())
	})

	It("rejects an unknown top-level field", func() {
		src := `{"schema":"polypkg.attestation-report/v1","generated_from":{"scope":"user","generations":[]},"packages":[],"extra":1}`
		_, err := ParseAttestationReport(strings.NewReader(src))
		Expect(err).To(HaveOccurred())
	})

	It("rejects a wrong schema id", func() {
		src := `{"schema":"polypkg.wrong/v1","generated_from":{"scope":"user","generations":[]},"packages":[]}`
		_, err := ParseAttestationReport(strings.NewReader(src))
		Expect(err).To(HaveOccurred())
	})

	It("rejects a package evidence missing content_hash", func() {
		src := `{"schema":"polypkg.attestation-report/v1","generated_from":{"scope":"user","generations":[1]},"packages":[{"name":"x","version":"1","generation":1,"installed_at":"2026-01-01T00:00:00Z"}]}`
		_, err := ParseAttestationReport(strings.NewReader(src))
		Expect(err).To(HaveOccurred())
	})
})
