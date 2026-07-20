package schema

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParsePin", func() {
	It("parses a fully-populated pin document", func() {
		good := `{
			"schema": "polypkg.pin/v1",
			"generation": 7,
			"pinned_at": "2026-05-26T12:00:00Z",
			"pinned_by": "alice",
			"pinned_reason": "baseline before deploy"
		}`
		p, err := ParsePin(strings.NewReader(good))
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Schema).To(Equal("polypkg.pin/v1"))
		Expect(p.Generation).To(Equal(7))
		Expect(p.PinnedBy).To(Equal("alice"))
		Expect(p.PinnedReason).To(Equal("baseline before deploy"))
		Expect(p.PinnedAt.IsZero()).To(BeFalse())
	})

	It("accepts an absent pinned_reason", func() {
		good := `{
			"schema": "polypkg.pin/v1",
			"generation": 1,
			"pinned_at": "2026-05-26T12:00:00Z",
			"pinned_by": "alice"
		}`
		p, err := ParsePin(strings.NewReader(good))
		Expect(err).NotTo(HaveOccurred())
		Expect(p.PinnedReason).To(BeEmpty())
	})

	It("rejects the wrong schema id", func() {
		bad := `{
			"schema": "polypkg.pin/v0",
			"generation": 1,
			"pinned_at": "2026-05-26T12:00:00Z",
			"pinned_by": "alice"
		}`
		_, err := ParsePin(strings.NewReader(bad))
		Expect(err).To(HaveOccurred())
	})

	It("rejects a document missing required fields", func() {
		missing := `{
			"schema": "polypkg.pin/v1",
			"generation": 1
		}`
		_, err := ParsePin(strings.NewReader(missing))
		Expect(err).To(HaveOccurred())
	})

	It("round-trips a Pin through Marshal/Parse", func() {
		p := &Pin{
			Schema:       "polypkg.pin/v1",
			Generation:   3,
			PinnedAt:     time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
			PinnedBy:     "bob",
			PinnedReason: "rollback target",
		}
		data, err := json.Marshal(p)
		Expect(err).NotTo(HaveOccurred())
		round, err := ParsePin(bytes.NewReader(data))
		Expect(err).NotTo(HaveOccurred())
		Expect(round.Schema).To(Equal(p.Schema))
		Expect(round.Generation).To(Equal(p.Generation))
		Expect(round.PinnedBy).To(Equal(p.PinnedBy))
		Expect(round.PinnedReason).To(Equal(p.PinnedReason))
		Expect(p.PinnedAt.Equal(round.PinnedAt)).To(BeTrue())
	})
})
