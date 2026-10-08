package cli

import (
	"bytes"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("plan and the audit log", func() {
	runPlanCmd := func(profilePath string) {
		GinkgoHelper()
		cmd := NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"plan", "--scope", "user", profilePath})
		// A first plan against empty state has changes pending: exit 2.
		Expect(cmd.Execute()).To(MatchError(errPlanChangesPending))
	}

	It("does not create audit.log", func() {
		env := sandboxUserEnv(GinkgoTB())
		profilePath := writeHelloProfile(env, publishUnattestedHello(), "")
		runPlanCmd(profilePath)
		Expect(filepath.Join(env, "state", "polypkg", "audit.log")).NotTo(BeAnExistingFile())
	})

	It("leaves an existing audit.log byte-for-byte unchanged", func() {
		env := sandboxUserEnv(GinkgoTB())
		profilePath := writeHelloProfile(env, publishUnattestedHello(), "")
		logPath := filepath.Join(env, "state", "polypkg", "audit.log")
		Expect(os.MkdirAll(filepath.Dir(logPath), 0o700)).To(Succeed())
		before := []byte(`{"schema":"polypkg.audit/v1","event":"apply.complete"}` + "\n")
		Expect(os.WriteFile(logPath, before, 0o600)).To(Succeed())

		runPlanCmd(profilePath)

		after, err := os.ReadFile(logPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before))
	})
})
