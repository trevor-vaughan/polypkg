package integration

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// serveDir starts an httptest.Server that file-serves dir and registers a
// cleanup so the server is closed when the test ends.
func serveDir(dir string) *httptest.Server {
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	DeferCleanup(srv.Close)
	return srv
}

// helloSourceDir creates a minimal package source tree for hello 1.0.0 under
// workDir/pkgs/hello, mirroring the action structure that buildHelloPackage uses
// so that apply succeeds end-to-end. Returns the path to the source directory.
func helloSourceDir(workDir string) string {
	srcDir := filepath.Join(workDir, "pkgs", "hello")
	Expect(os.MkdirAll(filepath.Join(srcDir, "content", "bin"), 0o755)).To(Succeed())

	manifest := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: dir
    params:
      path: $ACTIVE/hello/bin
      mode: "0o755"
  - phase: post-place
    action: install
    params:
      src: $PKG/content/bin/hi
      dest: $ACTIVE/hello/bin/hi
      policy: symlink
`
	Expect(os.WriteFile(filepath.Join(srcDir, "polypkg.yaml"), []byte(manifest), 0o644)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(srcDir, "content", "bin", "hi"),
		[]byte("#!/bin/sh\necho hello from polypkg\n"), 0o755)).To(Succeed())
	return srcDir
}

var _ = Describe("repo publisher", Ordered, func() {
	// Spec A — valid publisher output is consumed by the real client.
	Describe("builds a signed repo the client can search and install from", func() {
		var (
			workDir     string
			profilePath string
			srv         *httptest.Server
		)

		BeforeAll(func() {
			t := GinkgoTB()
			IsolatedEnv(t)
			t.Setenv("POLYPKG_REPO_KEY_PASSWORD", "pw")

			workDir = t.TempDir()
			repoDir := filepath.Join(workDir, "repo")
			keyDir := filepath.Join(workDir, "keys")
			manifest := filepath.Join(repoDir, "polypkg-repo.yaml")

			// Scaffold the repository. The source name must match what the profile
			// fixture names ("native"), because the trust document embeds the source
			// name and the client verifies it.
			out, err := runCmd("repo", "init", repoDir, "--source", "native", "--key-dir", keyDir)
			Expect(err).NotTo(HaveOccurred(), "repo init: %s", out)

			// Add hello 1.0.0.
			srcDir := helloSourceDir(workDir)
			out, err = runCmd("repo", "add", srcDir, "--manifest", manifest, "--key-dir", keyDir)
			Expect(err).NotTo(HaveOccurred(), "repo add: %s", out)

			// Serve the published directory.
			srv = serveDir(filepath.Join(repoDir, "public"))

			// Build the profile the consumer will use.
			trustRoot := filepath.Join(repoDir, "public", "trust_root.pub")
			profileContent := installHelloProfile(t, srv.URL, trustRoot)
			profilePath = filepath.Join(workDir, "profile.yaml")
			Expect(os.WriteFile(profilePath, []byte(profileContent), 0o644)).To(Succeed())

			// Expose the profile to commands that read POLYPKG_PROFILE.
			t.Setenv("POLYPKG_PROFILE", profilePath)
		})

		It("search finds hello in the published catalog", func() {
			out, err := runCmd("search", "hello")
			Expect(err).NotTo(HaveOccurred(), "search: %s", out)
			Expect(out).To(ContainSubstring("hello"))
		})

		It("apply installs hello from the publisher output", func() {
			out, err := runCmd("apply", profilePath)
			Expect(err).NotTo(HaveOccurred(), "apply: %s", out)
			Expect(out).To(ContainSubstring("applied generation"))
		})

		It("list shows hello as installed", func() {
			out, err := runCmd("list")
			Expect(err).NotTo(HaveOccurred(), "list: %s", out)
			Expect(out).To(ContainSubstring("hello"))
		})
	})

	// Spec B — a tampered artifact must be rejected.
	Describe("rejects a tampered artifact", func() {
		It("apply fails when the published artifact has been overwritten without re-signing", func() {
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
			out, err = runCmd("repo", "add", srcDir, "--manifest", manifest, "--key-dir", keyDir)
			Expect(err).NotTo(HaveOccurred(), "repo add: %s", out)

			// Overwrite the artifact with garbage — the .minisig is still the
			// original. The pool path is content-addressed, so resolve it from
			// the published index rather than guessing a name (writing to a
			// wrong path would silently leave the real blob intact).
			idxFile, err := os.Open(filepath.Join(repoDir, "public", "index.json"))
			Expect(err).NotTo(HaveOccurred())
			idx, err := schema.ParseIndex(idxFile)
			idxFile.Close()
			Expect(err).NotTo(HaveOccurred())
			Expect(idx.Packages["hello"]).NotTo(BeEmpty())
			artifactPath := filepath.Join(repoDir, "public", idx.Packages["hello"][0].Artifact)
			Expect(artifactPath).To(BeAnExistingFile())
			Expect(os.WriteFile(artifactPath, []byte("this is not a real artifact"), 0o644)).To(Succeed())

			srv := serveDir(filepath.Join(repoDir, "public"))

			trustRoot := filepath.Join(repoDir, "public", "trust_root.pub")
			profileContent := installHelloProfile(t, srv.URL, trustRoot)
			profilePath := filepath.Join(workDir, "profile.yaml")
			Expect(os.WriteFile(profilePath, []byte(profileContent), 0o644)).To(Succeed())

			_, err = runCmd("apply", profilePath)
			Expect(err).To(HaveOccurred(), "apply must reject tampered artifact")
			// The signature check runs before the hash check, so tampered bytes
			// surface as planner.ArtifactSignatureError ("signature verification
			// failed for <name>-<version> from source ..."), framed by the CLI
			// boundary with its Msg preserved. Pin the specific failure so a
			// regression to a generic apply error cannot pass.
			Expect(err.Error()).To(ContainSubstring("signature verification failed"),
				"tampered artifact must fail the signature check specifically")
		})
	})
})
