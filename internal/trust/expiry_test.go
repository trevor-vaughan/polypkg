package trust

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CheckExpiry", func() {
	// now is the injected clock for every spec so the skew boundary cases stay
	// deterministic regardless of wall-clock time.
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	var restore func()

	BeforeEach(func() {
		restore = SetTimeNowForTesting(func() time.Time { return now })
	})
	AfterEach(func() {
		restore()
	})

	It("accepts a future expires", func() {
		Expect(CheckExpiry("index", now.Add(time.Hour).Format(time.RFC3339))).To(Succeed())
	})

	It("rejects a past expires beyond the skew with the freeze-attack message", func() {
		err := CheckExpiry("index", now.Add(-expirySkew-time.Second).Format(time.RFC3339))
		Expect(err).To(MatchError(ContainSubstring("index expired at")))
		Expect(err).To(MatchError(ContainSubstring("stale metadata refused")))
	})

	It("accepts a past expires within the clock-skew tolerance", func() {
		Expect(CheckExpiry("index", now.Add(-expirySkew+time.Second).Format(time.RFC3339))).To(Succeed())
	})

	It("rejects an empty expires", func() {
		Expect(CheckExpiry("trust document", "")).To(MatchError(ContainSubstring("trust document has no expires field")))
	})

	It("rejects a non-RFC3339 expires", func() {
		Expect(CheckExpiry("index", "next tuesday")).To(MatchError(ContainSubstring("not RFC3339")))
	})
})
