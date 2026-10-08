package integration

import (
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// buildLocalRepoNamed is like buildLocalRepo but lets the caller control the
// source name embedded in the trust document.  The source name must match the
// name under which the repo will be registered in the consumer profile.
func buildLocalRepoNamed(workDir, sourceName string) (publicDir, trustRoot string) {
	repoDir := filepath.Join(workDir, "repo-"+sourceName)
	keyDir := filepath.Join(workDir, "keys-"+sourceName)
	manifest := filepath.Join(repoDir, "polypkg-repo.yaml")

	out, err := runCmd("repo", "init", repoDir, "--source", sourceName, "--key-dir", keyDir)
	Expect(err).NotTo(HaveOccurred(), "repo init (%s): %s", sourceName, out)

	srcDir := helloSourceDir(workDir)
	out, err = runCmd("repo", "add", srcDir, "--manifest", manifest, "--key-dir", keyDir)
	Expect(err).NotTo(HaveOccurred(), "repo add (%s): %s", sourceName, out)

	publicDir = filepath.Join(repoDir, "public")
	trustRoot = filepath.Join(publicDir, "trust_root.pub")
	return publicDir, trustRoot
}

var _ = Describe("manage sources with `polypkg source` and install from an added source", Ordered, func() {
	var (
		workDir         string
		nativePublicDir string
		nativeTrustRoot string
		extraPublicDir  string
		extraTrustRoot  string
		profilePath     string
	)

	BeforeAll(func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		t.Setenv("POLYPKG_REPO_KEY_PASSWORD", "pw")

		workDir = t.TempDir()

		// Build two independent signed local repos so each source name in the
		// consumer profile matches the name embedded in its trust document.
		// The trust document's .source field must equal the profile source name
		// or the client rejects verification — this is intentional security
		// design.  We reuse helloSourceDir for both (same content, separate
		// signing keys and trust chains).
		nativePublicDir, nativeTrustRoot = buildLocalRepoNamed(workDir, "native")
		extraPublicDir, extraTrustRoot = buildLocalRepoNamed(workDir, "extra")

		// Bootstrap a profile via the real `polypkg init` so we start with a
		// valid, comment-rich profile that source add/remove can edit in place.
		// IsolatedEnv sets XDG_CONFIG_HOME=<root>/config, so init writes
		// <root>/config/polypkg/profile.yaml (source "native").
		out, err := runCmd("init",
			"--source-url", "file://"+nativePublicDir,
			"--trust-root", nativeTrustRoot,
		)
		Expect(err).NotTo(HaveOccurred(), "init: %s", out)

		cfgHome := os.Getenv("XDG_CONFIG_HOME")
		profilePath = filepath.Join(cfgHome, "polypkg", "profile.yaml")
		Expect(profilePath).To(BeAnExistingFile(), "init must have written a profile")

		// Pin POLYPKG_PROFILE so every subsequent command uses this file
		// without requiring a positional path argument.
		t.Setenv("POLYPKG_PROFILE", profilePath)
	})

	It("source list shows the init-created source native", func() {
		out, err := runCmd("source", "list")
		Expect(err).NotTo(HaveOccurred(), "source list: %s", out)
		Expect(out).To(ContainSubstring("native"))
	})

	It("source list --format json returns a cli-result/v2 envelope with native", func() {
		out, err := runCmd("source", "list", "--format", "json")
		Expect(err).NotTo(HaveOccurred(), "source list --format json: %s", out)
		Expect(out).To(ContainSubstring(`"native"`))
	})

	It("source add registers an extra source backed by its own signed repo", func() {
		out, err := runCmd("source", "add", "extra",
			"--url", "file://"+extraPublicDir,
			"--trust-root", extraTrustRoot,
			"--type", "polypkg-native",
		)
		Expect(err).NotTo(HaveOccurred(), "source add extra: %s", out)
		Expect(out).To(ContainSubstring("extra"))
	})

	It("source list shows both native and extra after add", func() {
		out, err := runCmd("source", "list")
		Expect(err).NotTo(HaveOccurred(), "source list: %s", out)
		Expect(out).To(ContainSubstring("native"))
		Expect(out).To(ContainSubstring("extra"))
	})

	It("apply installs hello from the managed profile (both sources carry hello)", func() {
		// The profile written by init contains a commented-out packages block.
		// Overwrite it with an install-hello profile so apply has something to do.
		content, readErr := os.ReadFile(profilePath)
		Expect(readErr).NotTo(HaveOccurred())
		profileStr := string(content)

		// Replace the commented-out packages block with a real hello install.
		profileStr = strings.Replace(profileStr,
			"# packages:\n#   user:\n#     # Add packages here once the repo is reachable.  Examples:\n#     #   hello:\n#     #     version: \">=1.0.0\"   # any 1.x or newer\n#     #     version: \"=1.2.3\"    # pin exactly\n#     #     version: \"*\"         # latest available\n",
			"packages:\n  user:\n    hello:\n      version: \"=1.0.0\"\n",
			1)

		Expect(os.WriteFile(profilePath, []byte(profileStr), 0o600)).To(Succeed())

		out, err := runCmd("apply", profilePath)
		Expect(err).NotTo(HaveOccurred(), "apply: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))
	})

	It("list shows hello as installed", func() {
		out, err := runCmd("list")
		Expect(err).NotTo(HaveOccurred(), "list: %s", out)
		Expect(out).To(ContainSubstring("hello"))
	})

	It("source remove extra removes the extra source", func() {
		out, err := runCmd("source", "remove", "extra")
		Expect(err).NotTo(HaveOccurred(), "source remove extra: %s", out)
		Expect(out).To(ContainSubstring("extra"))
	})

	It("source list no longer shows extra after remove", func() {
		out, err := runCmd("source", "list")
		Expect(err).NotTo(HaveOccurred(), "source list: %s", out)
		Expect(out).To(ContainSubstring("native"))
		Expect(out).NotTo(ContainSubstring("extra"))
	})

	It("source remove native (the last source) is blocked with a friendly error", func() {
		_, err := runCmd("source", "remove", "native")
		Expect(err).To(HaveOccurred(), "removing the last source must fail")
		Expect(err.Error()).To(ContainSubstring("last source"))
	})
})
