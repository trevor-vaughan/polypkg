package schema

import (
	"bytes"
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PlanResult", func() {
	It("round-trips a minimal first-apply result", func() {
		p := &PlanResult{
			Schema:  "polypkg.plan/v1",
			Profile: "/tmp/profile.yaml",
			Exit:    1,
			Packages: PlanPackageDiff{
				Added: []ManifestEntry{{Name: "hello", Version: "1.0.0"}},
			},
		}
		data, err := json.Marshal(p)
		Expect(err).NotTo(HaveOccurred())
		round, err := ParsePlanResult(bytes.NewReader(data))
		Expect(err).NotTo(HaveOccurred())
		Expect(round.Profile).To(Equal("/tmp/profile.yaml"))
		Expect(round.Exit).To(Equal(1))
		Expect(round.Packages.Added).To(HaveLen(1))
	})

	It("round-trips with a current-gen block", func() {
		p := &PlanResult{
			Schema:  "polypkg.plan/v1",
			Profile: "/tmp/profile.yaml",
			Current: &PlanCurrentGen{Generation: 7},
			Exit:    0,
		}
		data, err := json.Marshal(p)
		Expect(err).NotTo(HaveOccurred())
		round, err := ParsePlanResult(bytes.NewReader(data))
		Expect(err).NotTo(HaveOccurred())
		Expect(round.Current).NotTo(BeNil())
		Expect(round.Current.Generation).To(Equal(7))
	})

	It("rejects an invalid schema version", func() {
		bad := []byte(`{"schema":"polypkg.plan/v0","profile":"x","exit":0}`)
		_, err := ParsePlanResult(bytes.NewReader(bad))
		Expect(err).To(HaveOccurred())
	})

	It("rejects exit codes outside 0/1/2", func() {
		bad := []byte(`{"schema":"polypkg.plan/v1","profile":"x","exit":3}`)
		_, err := ParsePlanResult(bytes.NewReader(bad))
		Expect(err).To(HaveOccurred())
	})
})
