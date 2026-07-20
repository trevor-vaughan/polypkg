package gc

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("ParseAge",
	func(in string, want time.Duration, ok bool) {
		got, err := ParseAge(in)
		if ok {
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(want))
		} else {
			Expect(err).To(HaveOccurred())
		}
	},
	Entry("30s", "30s", 30*time.Second, true),
	Entry("5m", "5m", 5*time.Minute, true),
	Entry("2h", "2h", 2*time.Hour, true),
	Entry("1d", "1d", 24*time.Hour, true),
	Entry("30d", "30d", 30*24*time.Hour, true),
	Entry("2w", "2w", 14*24*time.Hour, true),
	Entry("1h30m (standard time.ParseDuration form)", "1h30m", 90*time.Minute, true),
	Entry("0d (zero permitted)", "0d", time.Duration(0), true),
	Entry("empty rejected", "", time.Duration(0), false),
	Entry("junk rejected", "abc", time.Duration(0), false),
	Entry("1y rejected (no calendar arithmetic)", "1y", time.Duration(0), false),
	Entry("3M rejected (calendar months)", "3M", time.Duration(0), false),
	Entry("-5d rejected (negative)", "-5d", time.Duration(0), false),
)

var _ = Describe("Policy.Validate", func() {
	It("accepts count=1 age=0", func() {
		Expect(Policy{Count: 1, Age: 0}.Validate()).NotTo(HaveOccurred())
	})
	It("accepts user-scope defaults", func() {
		Expect(Policy{Count: 5, Age: 30 * 24 * time.Hour}.Validate()).NotTo(HaveOccurred())
	})
	It("rejects count=0 (would sweep everything)", func() {
		Expect(Policy{Count: 0, Age: time.Hour}.Validate()).To(HaveOccurred())
	})
	It("rejects count=-1", func() {
		Expect(Policy{Count: -1, Age: time.Hour}.Validate()).To(HaveOccurred())
	})
	It("rejects negative age", func() {
		Expect(Policy{Count: 5, Age: -time.Hour}.Validate()).To(HaveOccurred())
	})
})
