package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"
)

// newScopedCmdForTest builds a throwaway command carrying the --scope flag
// so resolveProfilePath can read it, mirroring apply/plan.
// cmdPath controls the Use field so cmd.CommandPath() reflects the caller
// (e.g. "polypkg apply" vs "polypkg plan").
func newScopedCmdForTest(scope string) *cobra.Command {
	return newScopedCmdForTestNamed("x", scope)
}

func newScopedCmdForTestNamed(use, scope string) *cobra.Command {
	cmd := &cobra.Command{Use: use}
	addScopeFlags(cmd)
	_ = cmd.Flags().Set("scope", scope)
	return cmd
}

var _ = Describe("resolveProfilePath", func() {
	var tmp string

	BeforeEach(func() {
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_CONFIG_HOME", tmp)
		if v, ok := os.LookupEnv("POLYPKG_PROFILE"); ok {
			GinkgoT().Setenv("POLYPKG_PROFILE", v) // register restore
		}
		_ = os.Unsetenv("POLYPKG_PROFILE")
	})

	It("prefers an explicit positional path", func() {
		p, err := resolveProfilePath(newScopedCmdForTest("user"), []string{"./x.yaml"})
		Expect(err).NotTo(HaveOccurred())
		Expect(p).To(Equal("./x.yaml"))
	})

	It("falls back to POLYPKG_PROFILE", func() {
		GinkgoT().Setenv("POLYPKG_PROFILE", "/tmp/env.yaml")
		p, err := resolveProfilePath(newScopedCmdForTest("user"), nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(p).To(Equal("/tmp/env.yaml"))
	})

	It("finds the first existing profile.{yaml,yml,jsonc,json} in the user config dir", func() {
		dir := filepath.Join(tmp, "polypkg")
		Expect(os.MkdirAll(dir, 0o700)).To(Succeed())
		want := filepath.Join(dir, "profile.yml")
		Expect(os.WriteFile(want, []byte("x"), 0o600)).To(Succeed())
		p, err := resolveProfilePath(newScopedCmdForTest("user"), nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(p).To(Equal(want))
	})

	It("prefers profile.yaml over later extensions when both exist", func() {
		dir := filepath.Join(tmp, "polypkg")
		Expect(os.MkdirAll(dir, 0o700)).To(Succeed())
		yaml := filepath.Join(dir, "profile.yaml")
		Expect(os.WriteFile(yaml, []byte("x"), 0o600)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "profile.json"), []byte("{}"), 0o600)).To(Succeed())
		p, err := resolveProfilePath(newScopedCmdForTest("user"), nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(p).To(Equal(yaml))
	})

	It("hints at POLYPKG_PROFILE for a command with no profile argument or flag", func() {
		// The test scaffold (Use: "x") takes no profile, like search or list.
		_, err := resolveProfilePath(newScopedCmdForTest("user"), nil)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("no profile found at"))
		Expect(ce.Hint).To(ContainSubstring("POLYPKG_PROFILE=<path>"))
		Expect(ce.Hint).NotTo(ContainSubstring("<profile-file>"))
	})

	It("hints at --profile for a command with a --profile flag", func() {
		cmd := newScopedCmdForTestNamed("install <package>...", "user")
		cmd.Flags().String("profile", "", "")
		_, err := resolveProfilePath(cmd, nil)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Hint).To(ContainSubstring("--profile <path>"))
	})

	It("uses the command path in the hint for a plan-shaped command", func() {
		planCmd := newScopedCmdForTestNamed("plan [profile-file]", "user")
		_, err := resolveProfilePath(planCmd, nil)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Hint).To(ContainSubstring("plan <profile-file>"))
		Expect(ce.Hint).NotTo(ContainSubstring("apply"))
	})

	It("searches /etc/polypkg for system scope", func() {
		_, err := resolveProfilePath(newScopedCmdForTest("system"), nil)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(Equal("no profile found at /etc/polypkg/profile.yaml"))
	})

	It("no-profile-found hint contains 'polypkg init'", func() {
		_, err := resolveProfilePath(newScopedCmdForTest("user"), nil)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Hint).To(ContainSubstring("polypkg init"), "hint must direct user to polypkg init")
	})
})

var _ = Describe("openProfileError", func() {
	It("returns does-not-exist CLIError with command-path hint", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "missing.yaml")
		_, ioErr := os.Open(path)
		Expect(ioErr).To(HaveOccurred())
		err := openProfileError(newScopedCmdForTestNamed("apply [profile-file]", "user"), path, ioErr)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("does not exist"))
		Expect(ce.Msg).To(ContainSubstring("missing.yaml"))
		Expect(ce.Hint).To(ContainSubstring("apply <profile-file>"))
	})

	It("uses plan in hint when invoked from plan command", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "missing.yaml")
		_, ioErr := os.Open(path)
		Expect(ioErr).To(HaveOccurred())
		err := openProfileError(newScopedCmdForTestNamed("plan [profile-file]", "user"), path, ioErr)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Hint).To(ContainSubstring("plan <profile-file>"))
		Expect(ce.Hint).NotTo(ContainSubstring("apply"))
	})

	It("returns permission CLIError for permission denied", func() {
		if os.Getuid() == 0 {
			Skip("running as root; permission tests do not apply")
		}
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "secret.yaml")
		Expect(os.WriteFile(path, []byte("x"), 0o000)).To(Succeed())
		_, ioErr := os.Open(path)
		Expect(ioErr).To(HaveOccurred())
		err := openProfileError(newScopedCmdForTestNamed("apply", "user"), path, ioErr)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("permission denied"))
		Expect(ce.Hint).To(ContainSubstring("--scope user"))
	})

	It("returns generic CLIError for other errors", func() {
		err := openProfileError(newScopedCmdForTestNamed("apply", "user"), "/some/path.yaml", fmt.Errorf("fake io error"))
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("cannot open profile"))
	})

	It("returns directory CLIError with file hint when path is a directory", func() {
		dir := GinkgoT().TempDir()
		err := openProfileError(newScopedCmdForTestNamed("apply [profile-file]", "user"), dir, syscall.EISDIR)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("is a directory"))
		Expect(ce.Msg).To(ContainSubstring(dir))
		Expect(ce.Hint).To(ContainSubstring("apply"))
		Expect(ce.Hint).To(ContainSubstring("profile-file"))
	})
})

var _ = Describe("installProfilePath hint (package actions)", func() {
	// installProfilePath must produce a --profile hint, not a positional one,
	// because install/remove/upgrade take package names positionally.

	BeforeEach(func() {
		GinkgoT().Setenv("XDG_CONFIG_HOME", GinkgoT().TempDir())
		if v, ok := os.LookupEnv("POLYPKG_PROFILE"); ok {
			GinkgoT().Setenv("POLYPKG_PROFILE", v)
		}
		_ = os.Unsetenv("POLYPKG_PROFILE")
	})

	It("no-profile error hint mentions --profile, not <profile-file>", func() {
		cmd := newInstallCmd()
		// installProfilePath reads --profile flag state, so exercise via the public wrapper.
		_, err := installProfilePath(cmd)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Hint).To(ContainSubstring("--profile"),
			"install hint must mention --profile; hint=%q", ce.Hint)
		Expect(ce.Hint).NotTo(ContainSubstring("<profile-file>"),
			"install hint must not mention positional; hint=%q", ce.Hint)
	})
})

var _ = Describe("plan command with directory path", func() {
	It("returns a CLIError naming the directory when passed a directory as profile", func() {
		dir := sandboxUserEnv(GinkgoTB())
		root := NewRootCmd()
		root.SetArgs([]string{"plan", dir})
		root.SetOut(GinkgoWriter)
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("is a directory"))
		Expect(ce.Msg).To(ContainSubstring(dir))
		Expect(ce.Hint).To(ContainSubstring("profile-file"))
	})
})

var _ = Describe("search with no profile", func() {
	It("hints at POLYPKG_PROFILE, not a <profile-file> argument search does not take", func() {
		sandboxUserEnv(GinkgoTB())
		GinkgoT().Setenv("POLYPKG_PROFILE", "")

		_, err := runSource("", "search", "hello")
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("no profile found at"))
		Expect(ce.Hint).To(ContainSubstring("POLYPKG_PROFILE=<path>"))
		Expect(ce.Hint).NotTo(ContainSubstring("<profile-file>"))
	})
})
