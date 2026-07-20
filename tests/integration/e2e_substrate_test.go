package integration

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/cli"
)

func unavailableSubstrateProfile(t testing.TB) string {
	t.Helper()
	g := NewWithT(t)
	p := installHelloProfile(t, "http://example.invalid", "/dev/null")
	g.Expect(p).To(ContainSubstring("substrate: store"), "fixture should declare the store substrate")
	return strings.ReplaceAll(p, "substrate: store", "substrate: sysext")
}

var _ = Describe("substrate availability", func() {
	It("apply fails closed when the substrate is unavailable", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(unavailableSubstrateProfile(t)), 0o644)).To(Succeed())

		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"apply", profilePath})
		err := cmd.Execute()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unsupported substrate"))

		dataHome := os.Getenv("XDG_DATA_HOME")
		_, statErr := os.Lstat(filepath.Join(dataHome, "polypkg", "active"))
		Expect(statErr).To(HaveOccurred(), "no generation may activate when the substrate is unavailable")
	})

	It("plan rejects an unavailable substrate", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(unavailableSubstrateProfile(t)), 0o644)).To(Succeed())

		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"plan", profilePath})
		err := cmd.Execute()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unsupported substrate"))
	})
})
