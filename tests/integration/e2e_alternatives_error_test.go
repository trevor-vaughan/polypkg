package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// altErrorProfile pins vim (a package that registers the "editor" alternative
// through a "vi" script) and extra (a plain package providing nothing), so the
// alternatives error paths can be driven against a real applied generation.
func altErrorProfile(repoURL, trustRoot string) string {
	return fmt.Sprintf(`schema: polypkg.spec/v1
name: alt-error-test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: %s
    trust_root: %s
packages:
  user:
    vim:
      version: "=1.0.0"
    extra:
      version: "=1.0.0"
`, repoURL, trustRoot)
}

var _ = Describe("alternatives set error paths", func() {
	BeforeEach(func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		vim := pkgProvidingAlt(t, "vim", "vi", "editor", 30)
		extra := buildPkg(t, "extra", "1.0.0", "#!/bin/sh\necho extra\n")
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "vim", version: "1.0.0", artifact: vim},
			indexPkg{name: "extra", version: "1.0.0", artifact: extra},
		)
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)
		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(altErrorProfile(srv.URL, trustRoot)), 0o644)).To(Succeed())
		GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
		out, err := runCmd("apply", profilePath)
		Expect(err).NotTo(HaveOccurred(), "apply: %s", out)
	})

	It("rejects set on an unknown alternative", func() {
		out, err := runAlternativesCmd("set", "bogus", "vim")
		Expect(err).To(HaveOccurred(), "set on unknown alternative must fail; output: %s", out)
		Expect(err.Error()).To(ContainSubstring(`unknown alternative "bogus"`))
	})

	It("rejects set when the package does not provide the alternative", func() {
		out, err := runAlternativesCmd("set", "editor", "extra")
		Expect(err).To(HaveOccurred(), "set on non-providing package must fail; output: %s", out)
		Expect(err.Error()).To(ContainSubstring(`package "extra" does not provide alternative "editor"`))
	})
})
