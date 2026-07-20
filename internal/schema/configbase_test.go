package schema

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ConfigBaseRelPath", func() {
	It("fans out by the first two hex characters and strips the algo prefix", func() {
		Expect(ConfigBaseRelPath("blake3:abcdef")).To(Equal("config-base/ab/abcdef"))
	})
})
