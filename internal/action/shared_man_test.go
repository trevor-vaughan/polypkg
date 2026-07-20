package action

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SharedManDir", func() {
	It("is the reserved man subtree name", func() {
		Expect(SharedManDir).To(Equal("man"))
	})
})
