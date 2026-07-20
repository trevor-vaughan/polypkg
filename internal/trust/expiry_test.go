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
		_, err := CheckExpiry("index", now.Add(time.Hour).Format(time.RFC3339), "")
		Expect(err).NotTo(HaveOccurred())
	})

	It("rejects a past expires beyond the skew with the freeze-attack message", func() {
		_, err := CheckExpiry("index", now.Add(-ExpirySkew-time.Second).Format(time.RFC3339), "")
		Expect(err).To(MatchError(ContainSubstring("index expired at")))
		Expect(err).To(MatchError(ContainSubstring("stale metadata refused")))
	})

	It("accepts a past expires within the clock-skew tolerance", func() {
		_, err := CheckExpiry("index", now.Add(-ExpirySkew+time.Second).Format(time.RFC3339), "")
		Expect(err).NotTo(HaveOccurred())
	})

	It("rejects an empty expires", func() {
		_, err := CheckExpiry("trust document", "", "")
		Expect(err).To(MatchError(ContainSubstring("trust document has no expires field")))
	})

	It("rejects a non-RFC3339 expires", func() {
		_, err := CheckExpiry("index", "next tuesday", "")
		Expect(err).To(MatchError(ContainSubstring("not RFC3339")))
	})

	It("grants grace to an expired doc within accept_expiry_until", func() {
		expired := now.Add(-ExpirySkew - time.Hour).Format(time.RFC3339)
		accept := now.Add(time.Hour).Format(time.RFC3339)
		graced, err := CheckExpiry("index", expired, accept)
		Expect(err).NotTo(HaveOccurred())
		Expect(graced).To(BeTrue(), "expired-but-within-grace must be accepted and reported graced")
	})

	It("still refuses an expired doc past accept_expiry_until", func() {
		expired := now.Add(-ExpirySkew - 2*time.Hour).Format(time.RFC3339)
		accept := now.Add(-time.Hour).Format(time.RFC3339) // ceiling already passed
		graced, err := CheckExpiry("index", expired, accept)
		Expect(err).To(HaveOccurred())
		Expect(graced).To(BeFalse())
	})

	It("does not grace a fresh doc (graced=false when not expired)", func() {
		fresh := now.Add(time.Hour).Format(time.RFC3339)
		accept := now.Add(48 * time.Hour).Format(time.RFC3339)
		graced, err := CheckExpiry("index", fresh, accept)
		Expect(err).NotTo(HaveOccurred())
		Expect(graced).To(BeFalse(), "a fresh doc is not graced even when a ceiling is set")
	})

	It("ignores an unparseable accept_expiry_until (fail closed to refusal)", func() {
		expired := now.Add(-ExpirySkew - time.Hour).Format(time.RFC3339)
		graced, err := CheckExpiry("index", expired, "not-a-date")
		Expect(err).To(HaveOccurred(), "a malformed ceiling must NOT grant infinite grace")
		Expect(graced).To(BeFalse())
	})

	It("empty accept_expiry_until means no grace (today's behavior)", func() {
		expired := now.Add(-ExpirySkew - time.Second).Format(time.RFC3339)
		graced, err := CheckExpiry("index", expired, "")
		Expect(err).To(HaveOccurred())
		Expect(graced).To(BeFalse())
	})
})
