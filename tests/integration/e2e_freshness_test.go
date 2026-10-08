package integration

import (
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// This spec substitutes for the container E2E tier's expired-metadata
// scenario: consumers get a 5-minute clock-skew tolerance, so a live
// binary cannot observe "expired" without sleeping out the skew window —
// unacceptable in the container matrix. Here the full CLI (real publisher,
// real signed repo over HTTP) runs with the trust clock advanced
// deterministically past expires+skew instead.
var _ = Describe("expired repository metadata", func() {
	It("refuses to install once the signed metadata has passed its validity window", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		t.Setenv("POLYPKG_REPO_KEY_PASSWORD", "pw")

		workDir := t.TempDir()
		repoDir := filepath.Join(workDir, "repo")
		keyDir := filepath.Join(workDir, "keys")
		manifest := filepath.Join(repoDir, "polypkg-repo.yaml")

		out, err := runCmd("repo", "init", repoDir, "--source", "native", "--key-dir", keyDir)
		Expect(err).NotTo(HaveOccurred(), "repo init: %s", out)

		srcDir := helloSourceDir(workDir)
		out, err = runCmd("repo", "add", srcDir, "--manifest", manifest, "--key-dir", keyDir,
			"--valid-for", "1h")
		Expect(err).NotTo(HaveOccurred(), "repo add: %s", out)

		srv := serveDir(filepath.Join(repoDir, "public"))

		trustRoot := filepath.Join(repoDir, "public", "trust_root.pub")
		profilePath := filepath.Join(workDir, "profile.yaml")
		Expect(os.WriteFile(profilePath,
			[]byte(installHelloProfile(t, srv.URL, trustRoot)), 0o644)).To(Succeed())

		// Sanity: within the validity window the very same repo installs fine,
		// so the refusal below is attributable to expiry alone.
		out, err = runCmd("apply", profilePath)
		Expect(err).NotTo(HaveOccurred(), "apply within validity window: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))

		// Advance the consumer's freshness clock past expires (1h) + skew (5m).
		restore := trust.SetTimeNowForTesting(func() time.Time {
			return time.Now().Add(1*time.Hour + 6*time.Minute)
		})
		DeferCleanup(restore)

		out, err = runCmd("apply", profilePath)
		Expect(err).To(HaveOccurred(), "apply must refuse expired metadata: %s", out)
		Expect(err.Error()).To(ContainSubstring("expired at"))
		Expect(err.Error()).To(ContainSubstring("stale metadata refused"))
	})
})
