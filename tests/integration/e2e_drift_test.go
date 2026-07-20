package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/cli"
)

// helloDriftPackage is a single-entry hello package whose `dir` action carries
// `drift: refuse` so a mode change blocks the next apply.
func helloDriftPackage(t testing.TB) []byte {
	t.Helper()
	manifest := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: dir
    drift: refuse
    params:
      path: $ACTIVE/hello/bin
      mode: "0o755"
`
	return buildTarZst(t, map[string]string{"polypkg.yaml": manifest})
}

func applyHelloOnce(t testing.TB, repoURL, trustRoot string, extraArgs ...string) (string, error) {
	t.Helper()
	profilePath := filepath.Join(t.TempDir(), "profile.yaml")
	if err := os.WriteFile(profilePath, []byte(installHelloProfile(t, repoURL, trustRoot)), 0o644); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	args := append([]string{"apply", profilePath}, extraArgs...)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

var _ = Describe("drift", func() {
	It("heals by swap under the default notify_heal policy", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		// Use the default-policy hello package (no `drift: refuse`).
		pkg := buildHelloPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())

		dataHome := os.Getenv("XDG_DATA_HOME")
		binPath := filepath.Join(dataHome, "polypkg", "active", "hello", "bin")
		// Drift the mode away from 0755.
		Expect(os.Chmod(binPath, 0o700)).To(Succeed())

		// Second apply: notify_heal default -> swap heals; apply succeeds.
		out, err := applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("applied generation"))
	})

	It("blocks under refuse policy and unblocks after accept-drift", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloDriftPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())

		dataHome := os.Getenv("XDG_DATA_HOME")
		binPath := filepath.Join(dataHome, "polypkg", "active", "hello", "bin")
		Expect(os.Chmod(binPath, 0o700)).To(Succeed())

		// Refuse policy blocks the apply.
		_, err = applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("apply refused"))

		// Run accept-drift and confirm the next apply proceeds.
		root := cli.NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"accept-drift", "hello/bin"})
		Expect(root.Execute()).To(Succeed())

		out, err := applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("applied generation"))
	})

	It("--heal-drift overrides refuse policy", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloDriftPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())

		dataHome := os.Getenv("XDG_DATA_HOME")
		Expect(os.Chmod(filepath.Join(dataHome, "polypkg", "active", "hello", "bin"), 0o700)).To(Succeed())

		out, err := applyHelloOnce(t, srv.URL, trustRoot, "--heal-drift")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("applied generation"))
	})

	It("captures install content hash on accept-drift so the next apply unblocks", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloInstallRefusePackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())

		dataHome := os.Getenv("XDG_DATA_HOME")
		livePath := filepath.Join(dataHome, "polypkg", "active", "hello", "payload")
		// Tamper the copied file's content to force a ReasonContent drift.
		Expect(os.WriteFile(livePath, []byte("tampered\n"), 0o644)).To(Succeed())

		// The refuse policy must block the second apply.
		_, err = applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("apply refused"))

		// accept-drift must capture the new content hash so the next apply unblocks.
		root := cli.NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"accept-drift", "hello/payload"})
		Expect(root.Execute()).To(Succeed())

		out, err := applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("applied generation"))
	})
})

// helloInstallRefusePackage uses install with policy=copy (so the live file is
// a real copy that can be mutated) and `drift: refuse` so a content change
// blocks the next apply.
func helloInstallRefusePackage(t testing.TB) []byte {
	t.Helper()
	manifest := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: install
    drift: refuse
    params:
      src: $PKG/payload
      dest: $ACTIVE/hello/payload
      policy: copy
`
	return buildTarZst(t, map[string]string{
		"polypkg.yaml": manifest,
		"payload":      "original\n",
	})
}
