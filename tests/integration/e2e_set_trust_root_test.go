package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// A repository rebuilt from scratch has a new signing key and serials that
// restart low. The consumer must refuse it until the operator explicitly
// re-pins, and `source set-trust-root` must then be enough on its own, even
// on a profile whose only source is the one being recovered (where
// `source remove` refuses to run).
var _ = Describe("source set-trust-root recovers a re-created repository", Ordered, func() {
	var (
		workDir   string
		repoDir   string
		keyDir    string
		manifest  string
		trustRoot string
	)

	// publish rebuilds the hello package with new script content so each call
	// produces a new signed index with a higher serial.
	publish := func(content string) {
		GinkgoHelper()
		script := filepath.Join(workDir, "pkgs", "hello", "content", "bin", "hi")
		Expect(os.WriteFile(script, []byte("#!/bin/sh\necho "+content+"\n"), 0o755)).To(Succeed())
		out, err := runCmd("repo", "build", "--manifest", manifest, "--key-dir", keyDir)
		Expect(err).NotTo(HaveOccurred(), "repo build: %s", out)
	}

	BeforeAll(func() {
		t := GinkgoTB()
		root := IsolatedEnv(t)
		t.Setenv("HOME", filepath.Join(root, "home"))
		t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
		t.Setenv("POLYPKG_REPO_KEY_PASSWORD", "pw")
		t.Setenv("POLYPKG_PROFILE", "")
		workDir = t.TempDir()

		var publicDir string
		publicDir, trustRoot = buildLocalRepoNamed(workDir, "native")
		repoDir = filepath.Join(workDir, "repo-native")
		keyDir = filepath.Join(workDir, "keys-native")
		manifest = filepath.Join(repoDir, "polypkg-repo.yaml")
		// Raise the serials the consumer will remember above what a fresh
		// repository starts at.
		publish("v2")
		publish("v3")

		out, err := runCmd("init", "--source-url", "file://"+publicDir, "--trust-root-file", trustRoot)
		Expect(err).NotTo(HaveOccurred(), "init: %s", out)
		out, err = runCmd("install", "hello")
		Expect(err).NotTo(HaveOccurred(), "install: %s", out)
	})

	It("refuses the re-created repository while the old key is pinned", func() {
		Expect(os.RemoveAll(repoDir)).To(Succeed())
		Expect(os.RemoveAll(keyDir)).To(Succeed())
		buildLocalRepoNamed(workDir, "native")

		out, err := runCmd("upgrade")
		Expect(err).To(HaveOccurred(), "upgrade must refuse a repository signed by an unpinned key: %s", out)
		Expect(err.Error()).To(ContainSubstring("Incompatible key identifiers"))
	})

	It("re-pins the single source with the publisher's key id", func() {
		out, err := runCmd("--format", "json", "repo", "key", "show", "--manifest", manifest, "--key-dir", keyDir)
		Expect(err).NotTo(HaveOccurred(), "repo key show: %s", out)
		var shown struct {
			Data struct {
				KeyID string `json:"key_id"`
			} `json:"data"`
		}
		Expect(json.Unmarshal([]byte(strings.TrimSpace(out)), &shown)).To(Succeed())
		Expect(shown.Data.KeyID).NotTo(BeEmpty())

		out, err = runCmd("source", "set-trust-root", "native",
			"--trust-root", trustRoot, "--trust-root-fingerprint", shown.Data.KeyID)
		Expect(err).NotTo(HaveOccurred(), "set-trust-root: %s", out)
		Expect(out).To(ContainSubstring("replaced trust root of source native"))
	})

	It("accepts the re-created repository despite its lower serials", func() {
		out, err := runCmd("upgrade")
		Expect(err).NotTo(HaveOccurred(), "upgrade after set-trust-root: %s", out)
	})
})
