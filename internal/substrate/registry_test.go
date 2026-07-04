package substrate

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Registry", func() {
	Describe("New", func() {
		It("constructs an *OwnStore for the 'store' substrate", func() {
			sub, err := New("store", GinkgoT().TempDir())
			Expect(err).NotTo(HaveOccurred())
			Expect(sub).NotTo(BeNil())
			_, ok := sub.(*OwnStore)
			Expect(ok).To(BeTrue(), "store should construct an *OwnStore")
		})

		DescribeTable("fails closed for unavailable substrates",
			func(name string) {
				_, err := New(name, GinkgoT().TempDir())
				Expect(err).To(HaveOccurred(), "name %q must fail closed", name)
				Expect(err.Error()).To(ContainSubstring("unsupported substrate"))
				Expect(err.Error()).To(ContainSubstring("available: store"))
			},
			Entry("sysext", "sysext"),
			Entry("bogus", "bogus"),
			Entry("empty", ""),
		)
	})

	Describe("Validate", func() {
		It("accepts 'store'", func() {
			Expect(Validate("store")).NotTo(HaveOccurred())
		})
		It("rejects 'sysext'", func() {
			Expect(Validate("sysext")).To(HaveOccurred())
		})
		It("rejects empty name", func() {
			Expect(Validate("")).To(HaveOccurred())
		})
	})
})
