package cli

import (
	"bytes"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/bridge"
)

var _ = Describe("writeBridgeSummary", func() {
	It("reports linked, pruned, and skipped with names", func() {
		var w bytes.Buffer
		writeBridgeSummary(&w, bridge.Result{
			Linked:  []string{"rg", "fd"},
			Pruned:  []string{"old"},
			Skipped: []bridge.Conflict{{Name: "bat", Existing: "/usr/bin/bat"}},
		}, "/home/t/.local/bin")
		out := w.String()
		Expect(out).To(ContainSubstring("linked 2 command(s)"))
		Expect(out).To(ContainSubstring("rg, fd"))
		Expect(out).To(ContainSubstring("unlinked 1"))
		Expect(out).To(ContainSubstring("skipped 1"))
		Expect(out).To(ContainSubstring("bat"))
	})

	It("emits nothing when the result is empty", func() {
		var w bytes.Buffer
		writeBridgeSummary(&w, bridge.Result{}, "/home/t/.local/bin")
		Expect(w.String()).To(BeEmpty())
	})

	It("adds a $PATH nudge when linked and dir is not on PATH", func() {
		GinkgoT().Setenv("PATH", "/usr/bin:/bin")
		var w bytes.Buffer
		writeBridgeSummary(&w, bridge.Result{Linked: []string{"rg"}}, "/somewhere/not/on/path")
		Expect(w.String()).To(ContainSubstring("not on your $PATH"))
	})

	It("omits the nudge when the dir is on PATH", func() {
		GinkgoT().Setenv("PATH", "/usr/bin:/opt/bin")
		var w bytes.Buffer
		writeBridgeSummary(&w, bridge.Result{Linked: []string{"rg"}}, "/opt/bin")
		Expect(w.String()).NotTo(ContainSubstring("$PATH"))
	})
})

var _ = Describe("link command no-generation error", func() {
	It("returns CLIError with apply hint when no generation exists", func() {
		sandboxUserEnv(GinkgoTB())
		root := NewRootCmd()
		root.SetArgs([]string{"link"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(Equal("no generation has been applied yet"))
		Expect(cliErr.Hint).To(Equal("run `polypkg apply` first"))
	})
})

var _ = Describe("bridgeBinDir gate", func() {
	It("returns empty when POLYPKG_BRIDGE_ENABLED is false", func() {
		GinkgoT().Setenv("XDG_CONFIG_HOME", GinkgoT().TempDir())
		GinkgoT().Setenv("POLYPKG_BRIDGE_ENABLED", "false")
		dir, err := bridgeBinDir("user", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(dir).To(Equal(""))
	})

	It("returns the bin dir when enabled (default)", func() {
		GinkgoT().Setenv("XDG_CONFIG_HOME", GinkgoT().TempDir())
		GinkgoT().Setenv("POLYPKG_BRIDGE_ENABLED", "")
		GinkgoT().Setenv("XDG_BIN_HOME", "/tmp/ppk-x/bin")
		dir, err := bridgeBinDir("user", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(dir).To(Equal("/tmp/ppk-x/bin"))
	})
})
