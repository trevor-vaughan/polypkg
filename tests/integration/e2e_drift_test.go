package integration

import (
	"archive/tar"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
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

	It("keeps a default-policy install unaffected by an edit to the extract cache", func() {
		t := GinkgoTB()
		t.Setenv("HOME", IsolatedEnv(t))
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: helloDefaultInstallPackage(t)})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())

		installed := filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "active", "hello", "bin", "hi")
		info, err := os.Lstat(installed)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().IsRegular()).To(BeTrue(),
			"the default install policy must place a real file, not a link into the extract cache")
		Expect(info.Mode().Perm()&0o100).NotTo(BeZero(), "the copy must stay executable")

		appendLine(extractCacheFile(t, "content/bin/hi"), "echo CACHE_TAMPERED")

		got, err := os.ReadFile(installed)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal(helloPayload))
		out, err := runStatusCmd("-vv")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("drift: 0 entries"))

		// The next apply must not copy the edited cache into the new generation:
		// the planner re-extracts the modified tree from the verified artifact.
		out, err = applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(ContainSubstring("applied generation"))
		got, err = os.ReadFile(installed)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal(helloPayload))
		got, err = os.ReadFile(extractCacheFile(t, "content/bin/hi"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal(helloPayload), "apply must restore the extract cache from the artifact")
	})

	It("reports a content edit to a default-policy install and apply heals it", func() {
		t := GinkgoTB()
		t.Setenv("HOME", IsolatedEnv(t))
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: helloDefaultInstallPackage(t)})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())

		installed := filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "active", "hello", "bin", "hi")
		Expect(os.WriteFile(installed, []byte("#!/bin/sh\necho tampered\n"), 0o755)).To(Succeed())

		out, err := runStatusCmd("-vv")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("hello/bin/hi (install): content [policy: notify_heal]"))

		out, err = applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(ContainSubstring("applied generation"))
		got, err := os.ReadFile(installed)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal(helloPayload))
		out, err = runStatusCmd("-vv")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("drift: 0 entries"))
	})

	It("reports an extract-cache edit behind a symlink-policy install and apply heals it", func() {
		t := GinkgoTB()
		t.Setenv("HOME", IsolatedEnv(t))
		repoDir := t.TempDir()
		// buildHelloPackage installs with an explicit `policy: symlink`.
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: buildHelloPackage(t)})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())

		installed := filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "active", "hello", "bin", "hi")
		appendLine(extractCacheFile(t, "content/bin/hi"), "echo CACHE_TAMPERED")

		out, err := runStatusCmd("-vv")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("hello/bin/hi (install): content [policy: notify_heal]"))

		out, err = applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(ContainSubstring("applied generation"))
		got, err := os.ReadFile(installed)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(ContainSubstring("echo hello from polypkg"))
		Expect(string(got)).NotTo(ContainSubstring("CACHE_TAMPERED"))
		out, err = runStatusCmd("-vv")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("drift: 0 entries"))
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

// helloPayload is the executable that helloDefaultInstallPackage ships.
const helloPayload = "#!/bin/sh\necho hello from polypkg\n"

// helloDefaultInstallPackage is a hello package whose install action omits
// `policy`, so it exercises the install default. The payload is executable so
// a test can check that the placed copy keeps the mode.
func helloDefaultInstallPackage(t testing.TB) []byte {
	t.Helper()
	g := NewWithT(t)
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
`
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, f := range []struct {
		name, body string
		mode       int64
	}{
		{"polypkg.yaml", manifest, 0o644},
		{"content/bin/hi", helloPayload, 0o755},
	} {
		g.Expect(tw.WriteHeader(&tar.Header{
			Name: f.name, Size: int64(len(f.body)), Mode: f.mode, Typeflag: tar.TypeReg,
		})).To(Succeed())
		_, err := io.WriteString(tw, f.body)
		g.Expect(err).NotTo(HaveOccurred())
	}
	g.Expect(tw.Close()).To(Succeed())
	var z bytes.Buffer
	enc, err := zstd.NewWriter(&z)
	g.Expect(err).NotTo(HaveOccurred())
	_, err = enc.Write(raw.Bytes())
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(enc.Close()).To(Succeed())
	return z.Bytes()
}

// extractCacheFile returns the path of rel inside hello-1.0.0's extract dir
// under the sandboxed XDG_STATE_HOME, failing unless exactly one dir matches.
func extractCacheFile(t testing.TB, rel string) string {
	t.Helper()
	g := NewWithT(t)
	matches, err := filepath.Glob(filepath.Join(os.Getenv("XDG_STATE_HOME"), "polypkg", "pkg-extract", "hello-1.0.0+*", rel))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(matches).To(HaveLen(1))
	return matches[0]
}

// appendLine appends line to the file at path, as an out-of-band edit would.
func appendLine(path, line string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	Expect(err).NotTo(HaveOccurred())
	_, err = f.WriteString(line + "\n")
	Expect(err).NotTo(HaveOccurred())
	Expect(f.Close()).To(Succeed())
}
