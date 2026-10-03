package config

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/gc"
)

// The precedence specs below exercise the loader itself, so they use keys that
// a consumer actually reads. Driving them from a registered-but-unread key
// would keep passing after the key stopped meaning anything.
var _ = Describe("Load", func() {
	It("applies defaults when no env or file is present", func() {
		cfg, err := Load(Options{Scope: ScopeUser, ConfigPaths: nil, EnvPrefix: "POLYPKG"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.GetString("revocation.near_expiry_threshold")).To(Equal("14d"))
		Expect(cfg.GetBool("bridge.enabled")).To(BeTrue())
	})

	It("lets env override default", func() {
		GinkgoT().Setenv("POLYPKG_REVOCATION_NEAR_EXPIRY_THRESHOLD", "7d")
		cfg, err := Load(Options{Scope: ScopeUser, ConfigPaths: nil, EnvPrefix: "POLYPKG"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.GetString("revocation.near_expiry_threshold")).To(Equal("7d"))
	})

	It("registers a default only for keys a consumer reads", func() {
		cfg, err := Load(Options{Scope: ScopeUser, EnvPrefix: "POLYPKG"})
		Expect(err).NotTo(HaveOccurred())
		// Registered here without a reader, these advertised settings that
		// silently did nothing; retention is configured in the profile.
		for _, dead := range []string{
			"lock.contention", "lock.stale_age_threshold",
			"retention.count", "retention.age",
			"audit.sinks.file.enabled", "audit.sinks.journald.enabled",
		} {
			Expect(cfg.IsSet(dead)).To(BeFalse(), "%s has no consumer and must not carry a default", dead)
		}
	})

	It("defaults bridge.enabled to true and lets env disable it", func() {
		cfg, err := Load(Options{Scope: ScopeUser, EnvPrefix: "POLYPKG"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.GetBool("bridge.enabled")).To(BeTrue())

		GinkgoT().Setenv("POLYPKG_BRIDGE_ENABLED", "false")
		cfg, err = Load(Options{Scope: ScopeUser, EnvPrefix: "POLYPKG"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.GetBool("bridge.enabled")).To(BeFalse())
	})

	It("lets file override default", func() {
		dir := GinkgoT().TempDir()
		cfgFile := filepath.Join(dir, "config.yaml")
		Expect(os.WriteFile(cfgFile, []byte("revocation:\n  near_expiry_threshold: 7d\n"), 0o644)).To(Succeed())

		cfg, err := Load(Options{Scope: ScopeUser, ConfigPaths: []string{dir}, EnvPrefix: "POLYPKG"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.GetString("revocation.near_expiry_threshold")).To(Equal("7d"))
	})

	It("lets env override file", func() {
		dir := GinkgoT().TempDir()
		cfgFile := filepath.Join(dir, "config.yaml")
		Expect(os.WriteFile(cfgFile, []byte("revocation:\n  near_expiry_threshold: 7d\n"), 0o644)).To(Succeed())
		GinkgoT().Setenv("POLYPKG_REVOCATION_NEAR_EXPIRY_THRESHOLD", "21d")

		cfg, err := Load(Options{Scope: ScopeUser, ConfigPaths: []string{dir}, EnvPrefix: "POLYPKG"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.GetString("revocation.near_expiry_threshold")).To(Equal("21d"))
	})
})

func TestNearExpiryThresholdDefaultParses(t *testing.T) {
	v, err := Load(Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := v.GetString("revocation.near_expiry_threshold")
	if got != "14d" {
		t.Fatalf("default = %q, want %q", got, "14d")
	}
	if _, err := gc.ParseAge(got); err != nil {
		t.Fatalf("default %q not parseable by gc.ParseAge: %v", got, err)
	}
}
