package schema

import (
	"bytes"
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("StatusResult", func() {
	It("round-trips a minimal no-generation result", func() {
		s := &StatusResult{Schema: "polypkg.status/v1", Retained: []StatusGenSummary{}}
		data, err := json.Marshal(s)
		Expect(err).NotTo(HaveOccurred())
		round, err := ParseStatusResult(bytes.NewReader(data))
		Expect(err).NotTo(HaveOccurred())
		Expect(round.Retained).To(BeEmpty())
		Expect(round.Current).To(BeNil())
	})

	It("round-trips a populated status", func() {
		s := &StatusResult{
			Schema:  "polypkg.status/v1",
			Current: &StatusCurrentGen{Generation: 3},
			Retained: []StatusGenSummary{
				{ID: 1, CommittedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
					Pinned: true, PinnedReason: "baseline", BytesOnDisk: 1024},
				{ID: 2, CommittedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
					BytesOnDisk: 2048},
				{ID: 3, CommittedAt: time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC),
					IsCurrent: true, BytesOnDisk: 4096},
			},
		}
		data, err := json.Marshal(s)
		Expect(err).NotTo(HaveOccurred())
		round, err := ParseStatusResult(bytes.NewReader(data))
		Expect(err).NotTo(HaveOccurred())
		Expect(round.Retained).To(HaveLen(3))
		Expect(round.Retained[0].Pinned).To(BeTrue())
		Expect(round.Retained[2].IsCurrent).To(BeTrue())
	})

	It("rejects bad schema version", func() {
		bad := []byte(`{"schema":"polypkg.status/v0","retained":[]}`)
		_, err := ParseStatusResult(bytes.NewReader(bad))
		Expect(err).To(HaveOccurred())
	})
})
