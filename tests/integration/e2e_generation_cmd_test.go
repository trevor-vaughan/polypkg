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

	It("refuses a bare invocation instead of printing help and succeeding", func() {
		IsolatedEnv(GinkgoTB())

		// Printing help and exiting 0 makes `polypkg generation` in a script
		// silently succeed having done nothing; the group must fail instead.
		out, err := runCmd("generation")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("polypkg generation requires a subcommand"))
		Expect(out).To(BeEmpty(), "help prose must not be written to stdout")
	})
})
