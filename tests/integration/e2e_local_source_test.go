package integration

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// buildLocalRepo scaffolds a signed repo at repoDir and returns the path to
// the published directory and its trust_root.pub file. It mirrors the setup
// in e2e_repo_test.go but operates on a purely local directory — no HTTP.
func buildLocalRepo(workDir string) (publicDir, trustRoot string) {
	repoDir := filepath.Join(workDir, "repo")
	keyDir := filepath.Join(workDir, "keys")
	manifest := filepath.Join(repoDir, "polypkg-repo.yaml")

	out, err := runCmd("repo", "init", repoDir, "--source", "native", "--key-dir", keyDir)
	Expect(err).NotTo(HaveOccurred(), "repo init: %s", out)

	srcDir := helloSourceDir(workDir)
	out, err = runCmd("repo", "add", srcDir, "--manifest", manifest, "--key-dir", keyDir)
	Expect(err).NotTo(HaveOccurred(), "repo add: %s", out)

	publicDir = filepath.Join(repoDir, "public")
	trustRoot = filepath.Join(publicDir, "trust_root.pub")
	return publicDir, trustRoot
}

var _ = Describe("local-filesystem source", func() {
	// Spec A — consumer installs from a file:// URI with no HTTP server.
	// This is the canonical stored form: init canonicalises bare absolute paths to
	// file:// before writing the profile, so file:// is what an on-disk profile
	// always contains.
	Describe("installs from a file:// URI (no HTTP)", Ordered, func() {
		var (
			workDir     string
			profilePath string
		)

		BeforeAll(func() {
			t := GinkgoTB()
			IsolatedEnv(t)
			t.Setenv("POLYPKG_REPO_KEY_PASSWORD", "pw")

			workDir = t.TempDir()
			publicDir, trustRoot := buildLocalRepo(workDir)

			// file:///abs/path is a valid URI and passes the profile's format:uri
			// schema constraint.
			localURL := "file://" + publicDir

			profileContent := installHelloProfile(t, localURL, trustRoot)
			profilePath = filepath.Join(workDir, "profile.yaml")
			Expect(os.WriteFile(profilePath, []byte(profileContent), 0o644)).To(Succeed())

			t.Setenv("POLYPKG_PROFILE", profilePath)
		})

		It("search finds hello in the local catalog", func() {
			out, err := runCmd("search", "hello")
			Expect(err).NotTo(HaveOccurred(), "search: %s", out)
			Expect(out).To(ContainSubstring("hello"))
		})

		It("apply installs hello from the local repo", func() {
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

	// Spec B — bare absolute path normalisation via polypkg init.
	// A bare absolute path is NOT a valid URI so it cannot appear in a profile's
	// url: field (format:uri rejects it). polypkg init is the normalisation gate:
	// it accepts the bare path and stores the canonical file:// form. This spec
	// exercises that gate and then proves the consumer can install via the
	// normalised URL.
	Describe("init normalises a bare absolute path to file://, consumer installs", Ordered, func() {
		var (
			workDir     string
			profilePath string
		)

		BeforeAll(func() {
			t := GinkgoTB()
			IsolatedEnv(t)
			t.Setenv("POLYPKG_REPO_KEY_PASSWORD", "pw")

			workDir = t.TempDir()
			publicDir, trustRoot := buildLocalRepo(workDir)

			// Pass the bare absolute path to init so it canonicalises to file://.
			// init writes a bootstrapped profile (no packages) to XDG_CONFIG_HOME.
			out, err := runCmd("init", "--source-url", publicDir, "--trust-root-file", trustRoot)
			Expect(err).NotTo(HaveOccurred(), "init with bare path: %s", out)

			// Verify init stored a file:// URI, not the bare path.
			cfgHome := os.Getenv("XDG_CONFIG_HOME")
			initProfilePath := filepath.Join(cfgHome, "polypkg", "profile.yaml")
			content, readErr := os.ReadFile(initProfilePath)
			Expect(readErr).NotTo(HaveOccurred(), "profile written by init not found at %s", initProfilePath)
			Expect(string(content)).To(ContainSubstring("file://"),
				"init must normalise the bare path to a file:// URI in the stored profile")

			// init writes a comment-only packages block (no installs). For the
			// consumer assertions we need a complete profile. Use installHelloProfile
			// with the normalised file:// URL that init would have stored.
			normalizedURL := "file://" + publicDir
			profileContent := installHelloProfile(t, normalizedURL, trustRoot)
			profilePath = filepath.Join(workDir, "profile.yaml")
			Expect(os.WriteFile(profilePath, []byte(profileContent), 0o644)).To(Succeed())

			t.Setenv("POLYPKG_PROFILE", profilePath)
		})

		It("init stores a file:// URI for a bare absolute path input", func() {
			// The BeforeAll assertion already verified this; re-state it here so
			// the failing spec name is descriptive if the normalization regresses.
			cfgHome := os.Getenv("XDG_CONFIG_HOME")
			initProfilePath := filepath.Join(cfgHome, "polypkg", "profile.yaml")
			content, err := os.ReadFile(initProfilePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(content)).To(ContainSubstring("file://"))
			Expect(string(content)).NotTo(ContainSubstring("url: "+workDir),
				"bare path must not appear verbatim in the stored profile")
		})

		It("search finds hello via the normalised local source", func() {
			out, err := runCmd("search", "hello")
			Expect(err).NotTo(HaveOccurred(), "search: %s", out)
			Expect(out).To(ContainSubstring("hello"))
		})

		It("apply installs hello from the normalised local source", func() {
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
})
