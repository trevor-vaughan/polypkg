package cli

import (
	"bytes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("plan attestation warnings", func() {
	It("prints the unattested warning to stderr under the default policy", func() {
		// Publish a real signed repo WITHOUT attestations (--skip-attestations
		// path) and plan against it with no attestation block in the profile:
		// the default warn policy must surface the unattested package on stderr.
		env := sandboxUserEnv(GinkgoTB())
		profilePath := writeHelloProfile(env, publishUnattestedHello(), "")

		cmd := NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		var out, errBuf bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errBuf)
		cmd.SetArgs([]string{"plan", "--scope", "user", profilePath})
		// First plan against an empty state has changes pending: the exit-2
		// sentinel, not a failure. Any other code means plan broke before it
		// could warn, and the stderr assertion below would be meaningless.
		Expect(ExitCode(cmd.Execute())).To(Equal(2))

		Expect(errBuf.String()).To(ContainSubstring("warning: package hello-1.0.0 is not attested"))
		Expect(out.String()).NotTo(ContainSubstring("not attested"),
			"warnings belong on stderr, not in the plan body")
	})
})
