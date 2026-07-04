package config

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Load", func() {
	It("applies defaults when no env or file is present", func() {
		cfg, err := Load(Options{Scope: ScopeUser, ConfigPaths: nil, EnvPrefix: "POLYPKG"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.GetString("lock.contention")).To(Equal("fail-fast"))
		Expect(cfg.GetInt("retention.count")).To(Equal(5))
		Expect(cfg.GetString("retention.age")).To(Equal("30d"))
	})

	It("lets env override default", func() {
		GinkgoT().Setenv("POLYPKG_LOCK_CONTENTION", "wait")
		cfg, err := Load(Options{Scope: ScopeUser, ConfigPaths: nil, EnvPrefix: "POLYPKG"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.GetString("lock.contention")).To(Equal("wait"))
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
		Expect(os.WriteFile(cfgFile, []byte("lock:\n  contention: wait\n"), 0o644)).To(Succeed())

		cfg, err := Load(Options{Scope: ScopeUser, ConfigPaths: []string{dir}, EnvPrefix: "POLYPKG"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.GetString("lock.contention")).To(Equal("wait"))
	})

	It("lets env override file", func() {
		dir := GinkgoT().TempDir()
		cfgFile := filepath.Join(dir, "config.yaml")
		Expect(os.WriteFile(cfgFile, []byte("lock:\n  contention: wait\n"), 0o644)).To(Succeed())
		GinkgoT().Setenv("POLYPKG_LOCK_CONTENTION", "wait-timeout")

		cfg, err := Load(Options{Scope: ScopeUser, ConfigPaths: []string{dir}, EnvPrefix: "POLYPKG"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.GetString("lock.contention")).To(Equal("wait-timeout"))
	})
})
