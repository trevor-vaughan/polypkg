package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/cli"
)

// M-4: post-edit rollback e2e — validation passes, edit written, apply fails.
// The fixture repo is real and signed; we chmod the data home 0o500 after the
// profile edit is written but before apply can create the generations directory,
// which forces apply to fail with a permission error. Non-root only.
var _ = Describe("install post-edit rollback", func() {
	It("restores the profile when apply fails after the edit is written", func() {
		if os.Getuid() == 0 {
			Skip("permission-based failure does not apply when running as root")
		}
		t := GinkgoTB()
		IsolatedEnv(t)

		artifact := buildTarZst(t, map[string]string{
			"polypkg.yaml": "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n",
		})
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: artifact})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		// Build a profile that does NOT include hello yet (bare name install will add it).
		profileContent := "schema: polypkg.spec/v1\nname: rollback-test\n" +
			"scopes:\n  user:\n    substrate: store\n" +
			"sources:\n  order: [native]\n  native:\n    type: polypkg-native\n" +
			"    url: " + srv.URL + "\n    trust_root: " + trustRoot + "\n" +
			"packages:\n  user: {}\n"
		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profileContent), 0o644)).To(Succeed())

		// Record the original profile bytes for the post-failure comparison.
		original, err := os.ReadFile(profilePath)
		Expect(err).NotTo(HaveOccurred())

		// Make the XDG_DATA_HOME/polypkg dir read-only BEFORE running install.
		// install's resolveAndEdit will MkdirAll the stateHome (which lives under
		// XDG_STATE_HOME — still writable), write the profile edit, release the
		// lock, and then call applyProfile. applyProfile calls MkdirAll(dataHome)
		// which fails on the read-only path, causing apply to fail after the edit.
		dataHome := filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg")
		Expect(os.MkdirAll(dataHome, 0o755)).To(Succeed())
		Expect(os.Chmod(dataHome, 0o500)).To(Succeed())
		defer os.Chmod(dataHome, 0o755) //nolint:errcheck

		root := cli.NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"install", "--profile", profilePath, "hello@1.0.0"})
		execErr := root.Execute()

		// Apply must have failed and reported the rollback.
		Expect(execErr).To(HaveOccurred(), "install must fail when apply cannot create the data home")
		Expect(execErr.Error()).To(ContainSubstring("the profile was not changed"),
			"error must carry the rollback annotation; got: %s\n output: %s", execErr.Error(), out.String())

		// Profile bytes must be byte-identical to the original.
		restored, rerr := os.ReadFile(profilePath)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(restored).To(Equal(original), "profile must be restored to its pre-edit state")
	})
})

// M-1: v-prefix normalization e2e — install hello@v1.0.0 writes "=1.0.0".
var _ = Describe("install v-prefix normalization", func() {
	It("strips the leading v from a bare version and writes the canonical constraint", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		artifact := buildTarZst(t, map[string]string{
			"polypkg.yaml": "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n",
		})
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: artifact})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		profileContent := "schema: polypkg.spec/v1\nname: vpfx-test\n" +
			"scopes:\n  user:\n    substrate: store\n" +
			"sources:\n  order: [native]\n  native:\n    type: polypkg-native\n" +
			"    url: " + srv.URL + "\n    trust_root: " + trustRoot + "\n" +
			"packages:\n  user: {}\n"
		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profileContent), 0o644)).To(Succeed())

		root := cli.NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"install", "--profile", profilePath, "hello@v1.0.0"})
		Expect(root.Execute()).To(Succeed())

		// The profile must now contain the canonical constraint "=1.0.0" (no v).
		edited, err := os.ReadFile(profilePath)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(edited)).To(ContainSubstring("=1.0.0"))
		Expect(string(edited)).NotTo(ContainSubstring("=v1.0.0"))
	})
})

var _ = Describe("single-package install", func() {
	It("installs a single package from a signed native repo", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		// Build a real tar.zst containing a minimal polypkg.yaml.
		artifact := buildTarZst(t, map[string]string{
			"polypkg.yaml": "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n",
		})

		// Serve a repo containing hello-1.0.0.tar.zst.
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: artifact})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		profileTmpl, err := os.ReadFile(filepath.Join("..", "fixtures", "profiles", "single-package.yaml"))
		Expect(err).NotTo(HaveOccurred())
		profileFinal := strings.ReplaceAll(string(profileTmpl), "file://FIXTURE_REPO", srv.URL)
		profileFinal = strings.ReplaceAll(profileFinal, "TRUST_ROOT", trustRoot)
		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profileFinal), 0o644)).To(Succeed())

		apply := cli.NewRootCmd()
		var out bytes.Buffer
		apply.SetOut(&out)
		apply.SetArgs([]string{"apply", profilePath})
		Expect(apply.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("applied generation"))

		// Confirm the manifest in the new generation includes hello.
		dataHome := os.Getenv("XDG_DATA_HOME")
		manifestPath := filepath.Join(dataHome, "polypkg", "generations", "1", "manifest.json")
		manifest, err := os.ReadFile(manifestPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(manifest)).To(ContainSubstring("hello"))
	})
})
