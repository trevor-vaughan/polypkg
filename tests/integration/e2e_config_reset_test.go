package integration

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// e2e_config_reset_test.go exercises `config reset` end-to-end: queue a
// package's preserve-policy config for reset, then prove the next apply
// restores the original content. The no-target error path is also covered.
var _ = Describe("config reset end-to-end", func() {
	var (
		profilePath string
		srv         *httptest.Server
	)

	BeforeEach(func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloConfigPackage(t, "original\n", "preserve", "1.0.0")
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv = httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)
		profilePath = filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(installHelloProfile(t, srv.URL, trustRoot)), 0o644)).To(Succeed())
		GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
		out, err := runCmd("apply", profilePath)
		Expect(err).NotTo(HaveOccurred(), "initial apply: %s", out)
	})

	It("queues a package's config for reset and restores it on the next apply", func() {
		// Tamper with the live config so the reset has something to restore.
		Expect(os.WriteFile(configLivePath(), []byte("tampered\n"), 0o644)).To(Succeed())

		out, err := runCmd("config", "reset", "--package", "hello", "--yes")
		Expect(err).NotTo(HaveOccurred(), "config reset: %s", out)
		Expect(out).To(ContainSubstring("queued 1 config path(s) for reset on next apply"))

		resetPath := filepath.Join(os.Getenv("XDG_STATE_HOME"), "polypkg", "pending-resets.json")
		Expect(resetPath).To(BeAnExistingFile())

		out, err = runCmd("apply", profilePath)
		Expect(err).NotTo(HaveOccurred(), "re-apply after reset: %s", out)

		restored, rerr := os.ReadFile(configLivePath())
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(restored)).To(Equal("original\n"),
			"reset must restore the original config content; got:\n%s", string(restored))
	})

	It("errors when no target is given", func() {
		out, err := runCmd("config", "reset")
		Expect(err).To(HaveOccurred(), "config reset with no target must fail; output: %s", out)
		Expect(err.Error()).To(ContainSubstring("config reset needs a target"))
	})
})
