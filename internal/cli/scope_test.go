package cli

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"

	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("scopeHomes", func() {
	It("resolves user homes from XDG", func() {
		dir := sandboxUserEnv(GinkgoTB())
		data, state, err := scopeHomes("user", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(data).To(Equal(filepath.Join(dir, "data", "polypkg")))
		Expect(state).To(Equal(filepath.Join(dir, "state", "polypkg")))
	})

	It("rejects a prefix with user scope", func() {
		_, _, err := scopeHomes("user", "/stage")
		Expect(err).To(MatchError(ContainSubstring("only to --scope system")))
	})

	It("resolves system homes at the real FHS paths with an empty prefix", func() {
		data, state, err := scopeHomes("system", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(data).To(Equal(paths.SystemDataDir()))
		Expect(state).To(Equal(paths.SystemStateDir()))
	})

	It("joins the prefix onto the system paths", func() {
		data, state, err := scopeHomes("system", "/stage")
		Expect(err).NotTo(HaveOccurred())
		Expect(data).To(Equal(filepath.Join("/stage", paths.SystemDataDir())))
		Expect(state).To(Equal(filepath.Join("/stage", paths.SystemStateDir())))
	})

	It("rejects an unknown scope", func() {
		_, _, err := scopeHomes("bogus", "")
		Expect(err).To(MatchError(ContainSubstring("invalid --scope")))
	})

	It("returns a CLIError for user scope with a prefix", func() {
		_, _, err := scopeHomes("user", "/x")
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue())
		Expect(cliErr.Msg).To(Equal("--prefix applies only to --scope system"))
		Expect(cliErr.Hint).To(Equal("drop --prefix, or pass --scope system"))
	})

	It("returns a CLIError for an invalid scope", func() {
		_, _, err := scopeHomes("bogus", "")
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue())
		Expect(cliErr.Msg).To(Equal(`invalid --scope "bogus"`))
		Expect(cliErr.Hint).To(Equal("expected user or system"))
	})
})

var _ = Describe("resolveScope", func() {
	newCmd := func() *cobra.Command {
		c := &cobra.Command{Use: "x", RunE: func(*cobra.Command, []string) error { return nil }}
		addScopeFlags(c)
		return c
	}
	profile := func(systemPrefix string) *schema.Profile {
		return &schema.Profile{Scopes: map[string]schema.ScopeSpec{
			"user":   {Substrate: "store"},
			"system": {Substrate: "store", Prefix: systemPrefix},
		}}
	}

	It("defaults to user scope with no prefix", func() {
		c := newCmd()
		Expect(c.ParseFlags(nil)).To(Succeed())
		scope, prefix, err := resolveScope(c, profile(""))
		Expect(err).NotTo(HaveOccurred())
		Expect(scope).To(Equal("user"))
		Expect(prefix).To(BeEmpty())
	})

	It("errors on --prefix with user scope", func() {
		c := newCmd()
		Expect(c.ParseFlags([]string{"--prefix", "/stage"})).To(Succeed())
		_, _, err := resolveScope(c, profile(""))
		Expect(err).To(MatchError(ContainSubstring("only to --scope system")))
	})

	It("uses the profile prefix for system scope when no flag or env is set", func() {
		c := newCmd()
		Expect(c.ParseFlags([]string{"--scope", "system"})).To(Succeed())
		GinkgoT().Setenv("POLYPKG_SYSTEM_PREFIX", "")
		scope, prefix, err := resolveScope(c, profile("/from-profile"))
		Expect(err).NotTo(HaveOccurred())
		Expect(scope).To(Equal("system"))
		Expect(prefix).To(Equal("/from-profile"))
	})

	It("prefers the env over the profile prefix", func() {
		c := newCmd()
		Expect(c.ParseFlags([]string{"--scope", "system"})).To(Succeed())
		GinkgoT().Setenv("POLYPKG_SYSTEM_PREFIX", "/from-env")
		_, prefix, err := resolveScope(c, profile("/from-profile"))
		Expect(err).NotTo(HaveOccurred())
		Expect(prefix).To(Equal("/from-env"))
	})

	It("prefers the flag over env and profile", func() {
		c := newCmd()
		Expect(c.ParseFlags([]string{"--scope", "system", "--prefix", "/from-flag"})).To(Succeed())
		GinkgoT().Setenv("POLYPKG_SYSTEM_PREFIX", "/from-env")
		_, prefix, err := resolveScope(c, profile("/from-profile"))
		Expect(err).NotTo(HaveOccurred())
		Expect(prefix).To(Equal("/from-flag"))
	})

	It("rejects an unknown scope", func() {
		c := newCmd()
		Expect(c.ParseFlags([]string{"--scope", "bogus"})).To(Succeed())
		_, _, err := resolveScope(c, profile(""))
		Expect(err).To(MatchError(ContainSubstring("invalid --scope")))
	})
})

var _ = Describe("scopeNearExpiryThreshold", func() {
	It("returns the 14d viper default when no config file is present", func() {
		// UserConfigHome resolves from XDG_CONFIG_HOME; an empty temp dir has no
		// config file, so the helper must fall back to the viper default 14d.
		GinkgoT().Setenv("XDG_CONFIG_HOME", GinkgoT().TempDir())
		d, err := scopeNearExpiryThreshold("user", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(d).To(Equal(14 * 24 * time.Hour))
	})
})

var _ = Describe("scopeDirMode", func() {
	It("is 0o755 for system and 0o700 for user", func() {
		Expect(scopeDirMode("system")).To(Equal(os.FileMode(0o755)))
		Expect(scopeDirMode("user")).To(Equal(os.FileMode(0o700)))
	})
})

var _ = Describe("scopeNames / scopeNamesStr", func() {
	It("returns sorted scope names", func() {
		p := &schema.Profile{Scopes: map[string]schema.ScopeSpec{
			"system": {Substrate: "store"},
			"user":   {Substrate: "store"},
		}}
		Expect(scopeNames(p)).To(Equal([]string{"system", "user"}))
		Expect(scopeNamesStr(p)).To(Equal("system, user"))
	})

	It("returns (none) when the profile has no scopes", func() {
		p := &schema.Profile{}
		Expect(scopeNamesStr(p)).To(Equal("(none)"))
	})
})

var _ = Describe("scope-aware host-dir resolvers", func() {
	It("scopeConfigEnabled defaults to true when the config dir is absent", func() {
		ok, err := scopeConfigEnabled("system", GinkgoT().TempDir(), "bridge.enabled")
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
	})

	It("bridgeBinDir joins the prefix onto /usr/local/bin for system scope", func() {
		dir, err := bridgeBinDir("system", "/stage")
		Expect(err).NotTo(HaveOccurred())
		Expect(dir).To(Equal(filepath.Join("/stage", "/usr/local/bin")))
	})

	It("bridgeBinDir returns the user bin home for user scope", func() {
		root := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_BIN_HOME", filepath.Join(root, "bin"))
		dir, err := bridgeBinDir("user", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(dir).To(Equal(filepath.Join(root, "bin")))
	})

	It("completionHostDirs returns the three system completion dirs under the prefix", func() {
		dirs, err := completionHostDirs("system", "/stage")
		Expect(err).NotTo(HaveOccurred())
		Expect(dirs).To(Equal(map[string]string{
			"bash": "/stage/usr/local/share/bash-completion/completions",
			"zsh":  "/stage/usr/local/share/zsh/site-functions",
			"fish": "/stage/usr/local/share/fish/vendor_completions.d",
		}))
	})

	It("desktopApplicationsDir and mimePackagesDir join the prefix for system scope", func() {
		d, err := desktopApplicationsDir("system", "/stage")
		Expect(err).NotTo(HaveOccurred())
		Expect(d).To(Equal("/stage/usr/local/share/applications"))
		m, err := mimePackagesDir("system", "/stage")
		Expect(err).NotTo(HaveOccurred())
		Expect(m).To(Equal("/stage/usr/local/share/mime/packages"))
	})

	It("a disabled gate yields empty regardless of scope", func() {
		GinkgoT().Setenv("POLYPKG_BRIDGE_ENABLED", "false")
		dir, err := bridgeBinDir("system", "/stage")
		Expect(err).NotTo(HaveOccurred())
		Expect(dir).To(BeEmpty())
	})
})
