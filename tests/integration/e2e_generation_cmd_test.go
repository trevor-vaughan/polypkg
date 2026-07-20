package integration

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("generation parent command", func() {
	It("errors on an unknown subcommand and points at status", func() {
		IsolatedEnv(GinkgoTB())

		// Text mode: error must name the bad subcommand.
		_, err := runCmd("generation", "list")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(`unknown generation subcommand "list"`))

		// JSON mode: hint must point at polypkg status.
		out, jerr := runCmd("generation", "--format", "json", "list")
		Expect(jerr).To(HaveOccurred())
		Expect(out).To(ContainSubstring("polypkg status"))
	})

	It("still prints help when invoked bare", func() {
		IsolatedEnv(GinkgoTB())
		out, err := runCmd("generation")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("pin"))
		Expect(out).To(ContainSubstring("unpin"))
	})
})
