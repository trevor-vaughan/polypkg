package integration

import (
	"fmt"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// profileWithHelloRange is a single-source profile whose hello requirement is
// a range rather than an exact pin, so a version the source withdraws can only
// be accepted through the exact-pin escape hatch.
func profileWithHelloRange(repoURL, trustRoot string) string {
	return fmt.Sprintf(`schema: polypkg.spec/v1
name: downgrade-test
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
    hello:
      version: ">=1.0.0"
`, repoURL, trustRoot)
}

var _ = Describe("anti-downgrade guard against a repo-built index", func() {
	// The planner tests drive the guard with handcrafted catalogs. This covers
	// the seam they cannot reach: a withdrawal the publisher actually makes
	// with `repo remove name@version`, as opposed to a re-add, which only
	// updates an entry in place and withdraws nothing.
	var keyDir, manifest, oldest string

	BeforeEach(func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		t.Setenv("POLYPKG_REPO_KEY_PASSWORD", "test-pw")

		work := GinkgoT().TempDir()
		repoDir := filepath.Join(work, "repo")
		keyDir = filepath.Join(work, "keys")
		manifest = filepath.Join(repoDir, "polypkg-repo.yaml")

		out, err := runCmd("repo", "init", repoDir, "--source", "native", "--key-dir", keyDir)
		Expect(err).NotTo(HaveOccurred(), "repo init: %s", out)
		oldest = helloSourceAtVersion(work, "1.0.0")
		for _, src := range []string{oldest, helloSourceAtVersion(work, "1.1.0")} {
			out, err = runCmd("repo", "add", src, "--manifest", manifest, "--key-dir", keyDir)
			Expect(err).NotTo(HaveOccurred(), "repo add %s: %s", src, out)
		}

		publicDir := filepath.Join(repoDir, "public")
		profilePath := filepath.Join(work, "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profileWithHelloRange(
			"file://"+publicDir, filepath.Join(publicDir, "trust_root.pub"))), 0o644)).To(Succeed())
		t.Setenv("POLYPKG_PROFILE", profilePath)

		out, err = runCmd("apply", profilePath)
		Expect(err).NotTo(HaveOccurred(), "apply: %s", out)
		out, err = runCmd("list")
		Expect(err).NotTo(HaveOccurred(), "list: %s", out)
		Expect(out).To(ContainSubstring("1.1.0"))
	})

	It("refuses to plan once the publisher withdraws the installed top version", func() {
		out, err := runCmd("repo", "remove", "hello@1.1.0", "--manifest", manifest, "--key-dir", keyDir)
		Expect(err).NotTo(HaveOccurred(), "repo remove: %s", out)

		out, err = runCmd("plan")
		Expect(err).To(HaveOccurred(), "plan must refuse the withdrawal downgrade: %s", out)
		Expect(err.Error()).To(ContainSubstring("refusing to downgrade hello to 1.0.0"))
		Expect(err.Error()).To(ContainSubstring("previously offered 1.1.0"))
	})

	It("plans cleanly when the publisher re-adds an older version it still serves", func() {
		out, err := runCmd("repo", "add", oldest, "--manifest", manifest, "--key-dir", keyDir)
		Expect(err).NotTo(HaveOccurred(), "repo add 1.0.0 again: %s", out)
		Expect(out).To(ContainSubstring("Added hello@1.0.0"))

		out, err = runCmd("plan")
		Expect(err).NotTo(HaveOccurred(),
			"1.1.0 is still in the signed index, so nothing was withdrawn: %s", out)
	})
})
