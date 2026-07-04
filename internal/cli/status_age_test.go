package cli

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("humanAge", func() {
	DescribeTable("renders the largest sensible unit",
		func(d time.Duration, want string) {
			Expect(humanAge(d)).To(Equal(want))
		},
		Entry("seconds", 42*time.Second, "42s"),
		Entry("sub-minute floor", 59*time.Second, "59s"),
		Entry("minutes — the old Round(hour) bug showed 0s here", 8*time.Minute, "8m"),
		Entry("minutes floor", 59*time.Minute+59*time.Second, "59m"),
		Entry("hours", 3*time.Hour+30*time.Minute, "3h"),
		Entry("days", 49*time.Hour, "2d"),
		Entry("minute boundary", 60*time.Second, "1m"),
		Entry("hour boundary", 60*time.Minute, "1h"),
		Entry("day boundary", 24*time.Hour, "1d"),
		Entry("negative clock skew clamps to zero", -5*time.Second, "0s"),
	)
})
