package integration

import (
	"encoding/json"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// helloSourceAtVersion scaffolds a hello package source at the given version,
// in its own directory so several versions coexist. helloSourceDir is the
// 1.0.0-only equivalent used by the single-version suites.
func helloSourceAtVersion(workDir, version string) string {
	srcDir := filepath.Join(workDir, "pkgs", "hello-"+version)
	Expect(os.MkdirAll(filepath.Join(srcDir, "content", "bin"), 0o755)).To(Succeed())

	manifest := `schema: polypkg.package/v1
name: hello
version: ` + version + `
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
		[]byte("#!/bin/sh\necho hello "+version+"\n"), 0o755)).To(Succeed())
	return srcDir
}

var _ = Describe("multi-version repositories", func() {
	// e2e_verbs_test.go already covers held-back reporting, but against a
	// handcrafted index served over httptest. This covers the seam that test
	// cannot reach: an index actually produced by `repo add`, twice.
	It("keeps an exact pin resolvable after the publisher publishes a newer version", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		t.Setenv("POLYPKG_REPO_KEY_PASSWORD", "test-pw")

		work := GinkgoT().TempDir()

		repoDir := filepath.Join(work, "repo")
		keyDir := filepath.Join(work, "keys")
		manifest := filepath.Join(repoDir, "polypkg-repo.yaml")

		out, err := runCmd("repo", "init", repoDir, "--source", "native", "--key-dir", keyDir)
		Expect(err).NotTo(HaveOccurred(), "repo init: %s", out)

		for _, v := range []string{"1.0.0", "1.1.0"} {
			out, err = runCmd("repo", "add", helloSourceAtVersion(work, v),
				"--manifest", manifest, "--key-dir", keyDir)
			Expect(err).NotTo(HaveOccurred(), "repo add %s: %s", v, out)
		}

		publicDir := filepath.Join(repoDir, "public")
		trustRoot := filepath.Join(publicDir, "trust_root.pub")

		// The index the publisher actually produced holds both versions.
		raw, rerr := os.ReadFile(filepath.Join(publicDir, "index.json"))
		Expect(rerr).NotTo(HaveOccurred())
		var idx schema.Index
		Expect(json.Unmarshal(raw, &idx)).To(Succeed())
		versions := make([]string, 0, 2)
		for _, e := range idx.Packages["hello"] {
			versions = append(versions, e.Version)
		}
		Expect(versions).To(ConsistOf("1.0.0", "1.1.0"),
			"repo add twice must publish both versions, not replace the first")

		// A client pinned to =1.0.0 resolves against that real index.
		profilePath := filepath.Join(work, "profile.yaml")
		Expect(os.WriteFile(profilePath,
			[]byte(profileWithTwoVersions("file://"+publicDir, trustRoot)), 0o644)).To(Succeed())
		GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)

		out, err = runCmd("apply", profilePath)
		Expect(err).NotTo(HaveOccurred(), "apply: %s", out)

		out, err = runCmd("list")
		Expect(err).NotTo(HaveOccurred(), "list: %s", out)
		Expect(out).To(ContainSubstring("1.0.0"))

		// The payoff: the pin is held back, not unsatisfiable.
		out, err = runCmd("upgrade")
		Expect(err).NotTo(HaveOccurred(),
			"upgrade must not fail on a pin the repository still serves: %s", out)
		Expect(out).To(ContainSubstring("held back: hello =1.0.0 (1.1.0 available)"))
		Expect(out).NotTo(ContainSubstring("no version matching"))
	})
})
