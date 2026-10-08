package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/trust"
)

var _ = Describe("apply attestation warnings", func() {
	It("prints the unattested warning to stderr under the default policy", func() {
		// Publish a real signed repo WITHOUT attestations (--skip-attestations
		// path) and apply against it with no attestation block in the profile:
		// the default warn policy must surface the unattested package on stderr
		// on the APPLY path too, not just plan (apply.go loops over
		// Result.AttestationWarnings identically).
		env := sandboxUserEnv(GinkgoTB())
		profilePath := writeHelloProfile(env, publishUnattestedHello(), "")

		cmd := NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		var out, errBuf bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errBuf)
		cmd.SetArgs([]string{"apply", "--scope", "user", profilePath})
		Expect(cmd.Execute()).To(Succeed())

		Expect(out.String()).To(ContainSubstring("applied generation 1"))
		Expect(errBuf.String()).To(ContainSubstring("warning: package hello-1.0.0 is not attested"))
		Expect(out.String()).NotTo(ContainSubstring("not attested"),
			"warnings belong on stderr, not in the apply body")
	})

	It("prints an unsuppressible SECURITY warning when a source sets tier: off", func() {
		// Same scaffolding as above, but the profile source disables its
		// attestation gate (tier: off). The planner routes such packages onto
		// Result.AttestationGateDisabled; apply must surface an UNCONDITIONAL
		// SECURITY warning on stderr (the un-silenceable per-source kill
		// switch) in addition to writing an audit event.
		env := sandboxUserEnv(GinkgoTB())
		profilePath := writeHelloProfile(env, publishUnattestedHello(), "    attestation:\n      tier: off\n")

		cmd := NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		var out, errBuf bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errBuf)
		cmd.SetArgs([]string{"apply", "--scope", "user", profilePath})
		Expect(cmd.Execute()).To(Succeed())

		stderr := errBuf.String()
		Expect(stderr).To(ContainSubstring("SECURITY"))
		Expect(stderr).To(ContainSubstring("hello-1.0.0"))
		Expect(stderr).To(ContainSubstring("gate disabled"))

		// The gate-off audit event records the package and its source as
		// DISCRETE fields (not "hello-1.0.0 (source repo)" mashed into one),
		// so an audit consumer can filter on source without string surgery.
		auditData, rerr := os.ReadFile(filepath.Join(env, "state", "polypkg", "audit.log"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(auditData)).To(ContainSubstring(`"event":"attestation.gate_off"`))
		Expect(string(auditData)).To(ContainSubstring(`"package":"hello-1.0.0"`))
		Expect(string(auditData)).To(ContainSubstring(`"source":"repo"`))
	})

	It("emits a loud SECURITY line and a metadata.expiry_graced audit event under grace", func() {
		// Same scaffolding as the tier:off spec, but instead of disabling the
		// attestation gate, the profile sets accept_expiry_until on the source
		// and the consumer clock is jumped past the published index's expires:
		// apply must accept the stale-but-signed index under grace AND surface
		// an unsuppressible SECURITY line plus a metadata.expiry_graced audit
		// event.
		env := sandboxUserEnv(GinkgoTB())
		profilePath := writeHelloProfile(env, publishUnattestedHello(),
			"    accept_expiry_until: \"2999-01-01T00:00:00Z\"\n")

		restore := trust.SetTimeNowForTesting(func() time.Time {
			return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
		})
		defer restore()

		cmd := NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		var out, errBuf bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errBuf)
		cmd.SetArgs([]string{"apply", "--scope", "user", profilePath})
		Expect(cmd.Execute()).To(Succeed())

		stderr := errBuf.String()
		Expect(stderr).To(ContainSubstring("SECURITY"))
		Expect(stderr).To(ContainSubstring("expired"))
		Expect(stderr).To(ContainSubstring("grace until 2999-01-01T00:00:00Z"))

		auditData, rerr := os.ReadFile(filepath.Join(env, "state", "polypkg", "audit.log"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(auditData)).To(ContainSubstring(`"event":"metadata.expiry_graced"`))
		Expect(string(auditData)).To(ContainSubstring(`"source":"repo"`))
		Expect(string(auditData)).To(ContainSubstring(`"accept_expiry_until":"2999-01-01T00:00:00Z"`))
	})
})
