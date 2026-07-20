package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/cli"
)

// helloConfigPackage builds a hello package with one config action. policy and the
// shipped content are parameterized so scenarios can vary them.
func helloConfigPackage(t testing.TB, content, policy, version string) []byte {
	t.Helper()
	manifest := fmt.Sprintf("schema: polypkg.package/v1\n"+
		"name: hello\nversion: %s\nactions:\n"+
		"  - phase: post-place\n    action: config\n    params:\n"+
		"      src: $PKG/app.conf\n      dest: $ACTIVE/hello/etc/app.conf\n"+
		"      policy: %s\n", version, policy)
	return buildTarZst(t, map[string]string{"polypkg.yaml": manifest, "app.conf": content})
}

// helloConfigPackageTwoFiles builds a hello package with two config actions,
// both using notify_preserve (preserve policy).
func helloConfigPackageTwoFiles(t testing.TB, content1, content2, version string) []byte {
	t.Helper()
	manifest := fmt.Sprintf("schema: polypkg.package/v1\n"+
		"name: hello\nversion: %s\nactions:\n"+
		"  - phase: post-place\n    action: config\n    params:\n"+
		"      src: $PKG/app.conf\n      dest: $ACTIVE/hello/etc/app.conf\n"+
		"      policy: preserve\n"+
		"  - phase: post-place\n    action: config\n    params:\n"+
		"      src: $PKG/extra.conf\n      dest: $ACTIVE/hello/etc/extra.conf\n"+
		"      policy: preserve\n", version)
	return buildTarZst(t, map[string]string{
		"polypkg.yaml": manifest,
		"app.conf":     content1,
		"extra.conf":   content2,
	})
}

// helloConfigPackageNoConfig builds a hello v2 package with NO config action
// (used for scenario 10 where the config action is dropped).
func helloConfigPackageNoConfig(t testing.TB, version string) []byte {
	t.Helper()
	manifest := fmt.Sprintf("schema: polypkg.package/v1\n"+
		"name: hello\nversion: %s\nactions: []\n", version)
	return buildTarZst(t, map[string]string{"polypkg.yaml": manifest})
}

// installHelloProfileV2 returns a profile pinning hello to version 2.0.0.
func installHelloProfileV2(t testing.TB, repoURL, trustRoot string) string {
	t.Helper()
	base := installHelloProfile(t, repoURL, trustRoot)
	return strings.ReplaceAll(base, `"=1.0.0"`, `"=2.0.0"`)
}

// configLivePath returns the path of the config file in the active root.
func configLivePath() string {
	return filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "active", "hello", "etc", "app.conf")
}

// configExtraPath returns the second config file path used in scenario 9.
func configExtraPath() string {
	return filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "active", "hello", "etc", "extra.conf")
}

// configAuditLog returns the path to the polypkg audit log.
func configAuditLog() string {
	return filepath.Join(os.Getenv("XDG_STATE_HOME"), "polypkg", "audit.log")
}

// applyHelloV2 re-signs the repo at serial 2 with a v2 package and applies it.
func applyHelloV2(t testing.TB, repoDir, repoURL string, v2pkg []byte) error {
	t.Helper()
	trustRoot2 := signRepo(t, repoDir, "native", 2,
		indexPkg{name: "hello", version: "2.0.0", artifact: v2pkg})
	profilePath := filepath.Join(t.TempDir(), "profile-v2.yaml")
	profile := installHelloProfileV2(t, repoURL, trustRoot2)
	if err := os.WriteFile(profilePath, []byte(profile), 0o644); err != nil {
		t.Fatalf("write v2 profile: %v", err)
	}
	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"apply", profilePath})
	return cmd.Execute()
}

var _ = Describe("config e2e", func() {
	// serve sets up a signed repo for v1 of the config package and starts an
	// HTTP server. It returns the server URL, trust root path, and a cleanup
	// function. The repoDir is also returned so callers can re-sign it for v2.
	serve := func(t testing.TB, pkg []byte) (repoDir, url, trustRoot string, stop func()) {
		repoDir = t.TempDir()
		trustRoot = signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		return repoDir, srv.URL, trustRoot, srv.Close
	}

	It("scenario 1: replace overwrites local edits", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloConfigPackage(t, "v1\n", "replace", "1.0.0")
		_, url, trust, stop := serve(t, pkg)
		defer stop()
		_, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(configLivePath(), []byte("hacked\n"), 0o644)).To(Succeed())
		_, err = applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())
		got, _ := os.ReadFile(configLivePath())
		Expect(string(got)).To(Equal("v1\n"))
	})

	It("scenario 2: preserve keeps local edits", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloConfigPackage(t, "v1\n", "preserve", "1.0.0")
		_, url, trust, stop := serve(t, pkg)
		defer stop()
		_, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(configLivePath(), []byte("local\n"), 0o644)).To(Succeed())
		_, err = applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())
		got, _ := os.ReadFile(configLivePath())
		Expect(string(got)).To(Equal("local\n"))
	})

	It("scenario 3: sticky preserve survives a second clean re-apply", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloConfigPackage(t, "v1\n", "preserve", "1.0.0")
		_, url, trust, stop := serve(t, pkg)
		defer stop()
		_, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(configLivePath(), []byte("local\n"), 0o644)).To(Succeed())
		_, err = applyHelloOnce(t, url, trust) // preserve fires
		Expect(err).NotTo(HaveOccurred())
		_, err = applyHelloOnce(t, url, trust) // no fresh drift; sticky must hold
		Expect(err).NotTo(HaveOccurred())
		got, _ := os.ReadFile(configLivePath())
		Expect(string(got)).To(Equal("local\n"))
	})

	It("scenario 4: preserve_warn keeps local edits and writes <dest>.new", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloConfigPackage(t, "v1\n", "preserve_warn", "1.0.0")
		_, url, trust, stop := serve(t, pkg)
		defer stop()
		_, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(configLivePath(), []byte("local\n"), 0o644)).To(Succeed())
		_, err = applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())
		got, _ := os.ReadFile(configLivePath())
		Expect(string(got)).To(Equal("local\n"))
		dotNew, err := os.ReadFile(configLivePath() + ".new")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(dotNew)).To(Equal("v1\n"))
	})

	It("scenario 5: three_way_merge clean — non-overlapping additions from both sides", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		// v1 content: three base lines
		v1Content := "a\nb\nc\n"
		pkg := helloConfigPackage(t, v1Content, "three_way_merge", "1.0.0")
		repoDir, url, trust, stop := serve(t, pkg)
		defer stop()
		_, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())

		// Operator prepends a line (non-overlapping with v2's addition)
		Expect(os.WriteFile(configLivePath(), []byte("LIVE\na\nb\nc\n"), 0o644)).To(Succeed())

		// v2 appends a different line at the end
		v2pkg := helloConfigPackage(t, "a\nb\nc\nINCOMING\n", "three_way_merge", "2.0.0")
		err = applyHelloV2(t, repoDir, url, v2pkg)
		Expect(err).NotTo(HaveOccurred())

		got, _ := os.ReadFile(configLivePath())
		Expect(string(got)).To(Equal("LIVE\na\nb\nc\nINCOMING\n"))
		Expect(string(got)).NotTo(ContainSubstring("<<<<<<<"))
	})

	It("scenario 6: three_way_merge conflict — overlapping edits produce markers and audit warning", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		v1Content := "a\nb\nc\n"
		pkg := helloConfigPackage(t, v1Content, "three_way_merge", "1.0.0")
		repoDir, url, trust, stop := serve(t, pkg)
		defer stop()
		_, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())

		// Operator edits line b → LIVE
		Expect(os.WriteFile(configLivePath(), []byte("a\nLIVE\nc\n"), 0o644)).To(Succeed())

		// v2 changes the same line b → INCOMING (conflict)
		v2pkg := helloConfigPackage(t, "a\nINCOMING\nc\n", "three_way_merge", "2.0.0")
		err = applyHelloV2(t, repoDir, url, v2pkg)
		Expect(err).NotTo(HaveOccurred())

		got, _ := os.ReadFile(configLivePath())
		Expect(string(got)).To(ContainSubstring("<<<<<<< LIVE"))

		auditBytes, err := os.ReadFile(configAuditLog())
		Expect(err).NotTo(HaveOccurred())
		Expect(string(auditBytes)).To(ContainSubstring("three_way_merge_conflicts"))
	})

	It("scenario 7: three_way_merge binary fallback — binary live triggers preserve_warn fallback", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		// v1 is a text file
		v1Content := "a\nb\n"
		pkg := helloConfigPackage(t, v1Content, "three_way_merge", "1.0.0")
		repoDir, url, trust, stop := serve(t, pkg)
		defer stop()
		_, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())

		// Operator writes a binary file (contains NUL byte)
		Expect(os.WriteFile(configLivePath(), []byte("a\x00b\n"), 0o644)).To(Succeed())

		// v2 ships a new text version
		v2pkg := helloConfigPackage(t, "a\nb\nc\n", "three_way_merge", "2.0.0")
		err = applyHelloV2(t, repoDir, url, v2pkg)
		Expect(err).NotTo(HaveOccurred())

		// Binary live triggers preserve_warn fallback: live preserved, .new written
		got, _ := os.ReadFile(configLivePath())
		Expect(got).To(Equal([]byte("a\x00b\n")))
		dotNew, err := os.ReadFile(configLivePath() + ".new")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(dotNew)).To(Equal("a\nb\nc\n"))
	})

	It("scenario 8: reset discards local edits and restores package content", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloConfigPackage(t, "v1\n", "preserve", "1.0.0")
		_, url, trust, stop := serve(t, pkg)
		defer stop()
		_, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(configLivePath(), []byte("local\n"), 0o644)).To(Succeed())
		_, err = applyHelloOnce(t, url, trust) // preserve fires
		Expect(err).NotTo(HaveOccurred())

		root := cli.NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"config", "reset", "hello/etc/app.conf", "--yes"})
		Expect(root.Execute()).To(Succeed())

		_, err = applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())
		got, _ := os.ReadFile(configLivePath())
		Expect(string(got)).To(Equal("v1\n"))
	})

	It("scenario 9: reset --package resets all config files owned by the package", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloConfigPackageTwoFiles(t, "app-v1\n", "extra-v1\n", "1.0.0")
		_, url, trust, stop := serve(t, pkg)
		defer stop()
		_, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())

		// Edit both live config files.
		Expect(os.WriteFile(configLivePath(), []byte("local-app\n"), 0o644)).To(Succeed())
		Expect(os.WriteFile(configExtraPath(), []byte("local-extra\n"), 0o644)).To(Succeed())

		// Second apply: both preserve.
		_, err = applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())
		gotApp, _ := os.ReadFile(configLivePath())
		Expect(string(gotApp)).To(Equal("local-app\n"))
		gotExtra, _ := os.ReadFile(configExtraPath())
		Expect(string(gotExtra)).To(Equal("local-extra\n"))

		// Queue reset for the entire hello package.
		root := cli.NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"config", "reset", "--package", "hello", "--yes"})
		Expect(root.Execute()).To(Succeed())

		// Third apply: both config files restored to package content.
		_, err = applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())
		gotApp, _ = os.ReadFile(configLivePath())
		Expect(string(gotApp)).To(Equal("app-v1\n"))
		gotExtra, _ = os.ReadFile(configExtraPath())
		Expect(string(gotExtra)).To(Equal("extra-v1\n"))
	})

	It("scenario 10: reset for missing entry — queue is cleared and config_reset_skipped warning emitted", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		// v1 has a config action; v2 drops it entirely.
		pkg := helloConfigPackage(t, "v1\n", "preserve", "1.0.0")
		repoDir, url, trust, stop := serve(t, pkg)
		defer stop()
		_, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(configLivePath(), []byte("local\n"), 0o644)).To(Succeed())
		_, err = applyHelloOnce(t, url, trust) // preserve fires
		Expect(err).NotTo(HaveOccurred())

		// Queue a reset for the path that v2 will no longer own.
		root := cli.NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"config", "reset", "hello/etc/app.conf", "--yes"})
		Expect(root.Execute()).To(Succeed())

		// v2 drops the config action.
		v2pkg := helloConfigPackageNoConfig(t, "2.0.0")
		err = applyHelloV2(t, repoDir, url, v2pkg)
		Expect(err).NotTo(HaveOccurred(), "apply must succeed even when the queued path is no longer present")

		// Queue file cleared.
		stateHome := os.Getenv("XDG_STATE_HOME")
		resetsPath := filepath.Join(stateHome, "polypkg", "pending-resets.json")
		_, statErr := os.Stat(resetsPath)
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "pending-resets.json must be cleared after apply")

		// config_reset_skipped warning in audit log.
		auditBytes, err := os.ReadFile(configAuditLog())
		Expect(err).NotTo(HaveOccurred())
		Expect(string(auditBytes)).To(ContainSubstring("config_reset_skipped"))
	})
})
