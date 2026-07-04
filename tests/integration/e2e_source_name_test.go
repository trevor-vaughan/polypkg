package integration

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// A repository published under a non-default source name ("handtest") must not
// silently wedge a profile whose source entry is named "native": the mismatch
// has to surface as the exact trust error plus an actionable recovery hint
// (source add <name> / init --source-name <name>).
var _ = Describe("source-name mismatch recovery hint", Ordered, func() {
	BeforeAll(func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		// Publish a complete signed repo bound to source "handtest"...
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "handtest", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: helloArtifact(t)})

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)

		// ...but consume it through a profile whose source entry is "native".
		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath,
			[]byte(installHelloProfile(t, srv.URL, trustRoot)), 0o644)).To(Succeed())
		t.Setenv("POLYPKG_PROFILE", profilePath)
	})

	It("refuses with the mismatch error and a recovery hint", func() {
		// JSON mode: the in-process harness returns the error but never runs
		// main's RenderError, so the hint is only observable in the emitted
		// cli-result envelope (text-mode hints are printed by RenderError).
		out, err := runCmd("search", "anything", "--format", "json")
		Expect(err).To(HaveOccurred())
		combined := out + err.Error()
		Expect(combined).To(ContainSubstring(`trust document is for source "handtest", expected "native"`))
		Expect(combined).To(ContainSubstring(`source add handtest`))
		Expect(combined).To(ContainSubstring(`--source-name handtest`))
	})
})
