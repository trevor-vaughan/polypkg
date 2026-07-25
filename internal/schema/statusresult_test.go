package schema

import (
	"bytes"
	"encoding/json"
	"strings"
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

	It("round-trips a status result carrying freshness_grace", func() {
		const j = `{"schema":"polypkg.status/v1","retained":[],` +
			`"freshness_grace":[{"source":"repo","accept_until":"2999-01-01T00:00:00Z","docs":["index","trust document"],"window_expired":false}]}`
		sr, err := ParseStatusResult(strings.NewReader(j))
		Expect(err).NotTo(HaveOccurred())
		Expect(sr.FreshnessGrace).To(HaveLen(1))
		Expect(sr.FreshnessGrace[0].Source).To(Equal("repo"))
		Expect(sr.FreshnessGrace[0].Docs).To(Equal([]string{"index", "trust document"}))
		Expect(sr.FreshnessGrace[0].WindowExpired).To(BeFalse())
	})

	It("round-trips a status result carrying revoked_builders", func() {
		const j = `{"schema":"polypkg.status/v1","retained":[],` +
			`"revoked_builders":[{"package":"hello","version":"1.0.0","key_id":"builder-a"}]}`
		sr, err := ParseStatusResult(strings.NewReader(j))
		Expect(err).NotTo(HaveOccurred())
		Expect(sr.RevokedBuilders).To(HaveLen(1))
		Expect(sr.RevokedBuilders[0].Package).To(Equal("hello"))
		Expect(sr.RevokedBuilders[0].KeyID).To(Equal("builder-a"))
	})

	It("round-trips a status result carrying revoked_attestations", func() {
		const j = `{"schema":"polypkg.status/v1","retained":[],` +
			`"revoked_attestations":[{"package":"acme","version":"1.0.0","attestation_hash":"blake3:deadbeef"}]}`
		sr, err := ParseStatusResult(strings.NewReader(j))
		Expect(err).NotTo(HaveOccurred())
		Expect(sr.RevokedAttestations).To(HaveLen(1))
		Expect(sr.RevokedAttestations[0].Package).To(Equal("acme"))
		Expect(sr.RevokedAttestations[0].AttestationHash).To(Equal("blake3:deadbeef"))
	})

	It("round-trips a status result carrying revocation_freshness", func() {
		const j = `{"schema":"polypkg.status/v1","retained":[],` +
			`"revocation_freshness":[{"source":"acme","expires":"2026-07-01T00:00:00Z","state":"expired","acknowledged":false}]}`
		sr, err := ParseStatusResult(strings.NewReader(j))
		Expect(err).NotTo(HaveOccurred())
		Expect(sr.RevocationFreshness).To(HaveLen(1))
		Expect(sr.RevocationFreshness[0].Source).To(Equal("acme"))
		Expect(sr.RevocationFreshness[0].Expires).To(Equal("2026-07-01T00:00:00Z"))
		Expect(sr.RevocationFreshness[0].State).To(Equal("expired"))
		Expect(sr.RevocationFreshness[0].Acknowledged).To(BeFalse())
	})

	It("rejects bad schema version", func() {
		bad := []byte(`{"schema":"polypkg.status/v0","retained":[]}`)
		_, err := ParseStatusResult(bytes.NewReader(bad))
		Expect(err).To(HaveOccurred())
	})
})
