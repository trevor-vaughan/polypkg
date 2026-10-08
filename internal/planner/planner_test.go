package planner

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("Plan", func() {
	It("rejects a profile with no matching scope", func() {
		p := &schema.Profile{
			Schema: "polypkg.spec/v1", Name: "test",
			Scopes: map[string]schema.ScopeSpec{"system": {Substrate: "store"}},
			Sources: schema.SourcesSpec{
				Order:   []string{"native"},
				Sources: map[string]schema.SourceBackend{"native": {Type: "native", URL: "https://x.invalid", TrustRoot: "/dev/null"}},
			},
		}
		_, err := Plan(GinkgoT().Context(), p, Options{Scope: "user"})
		Expect(err).To(MatchError(ContainSubstring(`no "user" scope`)))
	})

	It("returns an empty result for a no-package profile", func() {
		p := &schema.Profile{
			Schema: "polypkg.spec/v1", Name: "test",
			Scopes: map[string]schema.ScopeSpec{"user": {Substrate: "store"}},
			Sources: schema.SourcesSpec{
				Order:   []string{"native"},
				Sources: map[string]schema.SourceBackend{"native": {Type: "native", URL: "https://x.invalid", TrustRoot: "/dev/null"}},
			},
		}
		res, err := Plan(GinkgoT().Context(), p, Options{Scope: "user", DataHome: GinkgoT().TempDir(), StateHome: GinkgoT().TempDir()})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Entries).To(BeEmpty())
		Expect(res.Manifest.Entries).To(BeEmpty())
		Expect(res.Ownership.Entries).To(BeEmpty())
	})

	It("selects only the requested scope's packages (no cross-scope union)", func() {
		// Packages live only under "system"; planning the "user" scope must
		// resolve an empty requirement set and return the no-package result
		// without touching the (unreachable) source. Under the prior union bug
		// the system package would be pulled in and Plan would try (and fail) to
		// reach the source.
		p := &schema.Profile{
			Schema: "polypkg.spec/v1", Name: "test",
			Scopes: map[string]schema.ScopeSpec{
				"user":   {Substrate: "store"},
				"system": {Substrate: "store"},
			},
			Sources: schema.SourcesSpec{
				Order:   []string{"native"},
				Sources: map[string]schema.SourceBackend{"native": {Type: "native", URL: "https://x.invalid", TrustRoot: "/dev/null"}},
			},
			Packages: map[string]map[string]schema.PackageRef{
				"system": {"ghost": {Version: "=1.0.0"}},
			},
		}
		res, err := Plan(GinkgoT().Context(), p, Options{Scope: "user"})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Entries).To(BeEmpty())
	})

	// Full-fetch integration tests (with httptest server, signed repo, etc.)
	// live in tests/integration/e2e_plan_test.go. The unit-level
	// tests here focus on the no-network paths and error returns.
})

var _ = Describe("package file selection", func() {
	It("opens polypkg.yaml when only yaml present", func() {
		dir := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte("y"), 0o644)).To(Succeed())
		f, name, err := openPackageFile(dir)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(name).To(Equal("polypkg.yaml"))
	})

	It("opens polypkg.jsonc when only jsonc present", func() {
		dir := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(dir, "polypkg.jsonc"), []byte("j"), 0o644)).To(Succeed())
		f, name, err := openPackageFile(dir)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		Expect(name).To(Equal("polypkg.jsonc"))
	})

	It("rejects a tarball that contains both polypkg.yaml and polypkg.jsonc", func() {
		dir := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte("y"), 0o644)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "polypkg.jsonc"), []byte("j"), 0o644)).To(Succeed())
		_, _, err := openPackageFile(dir)
		Expect(err).To(MatchError(ContainSubstring("ambiguous package format")))
	})

	It("returns a clear error when neither file is present", func() {
		dir := GinkgoT().TempDir()
		_, _, err := openPackageFile(dir)
		Expect(err).To(MatchError(ContainSubstring("no polypkg.yaml or polypkg.jsonc")))
	})
})
