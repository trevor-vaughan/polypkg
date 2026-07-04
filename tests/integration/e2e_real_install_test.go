package integration

import (
	"archive/tar"
	"bytes"
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

// buildHelloPackage creates a hello-1.0.0.tar.zst with a polypkg.yaml
// declaring install + dir actions and a content/bin/hi script.
func buildHelloPackage(t testing.TB) []byte {
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
      policy: symlink
`
	hi := "#!/bin/sh\necho hello from polypkg\n"

	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	files := []struct {
		name    string
		content string
		mode    int64
	}{
		{"polypkg.yaml", manifest, 0o644},
		{"content/bin/hi", hi, 0o755},
	}
	for _, f := range files {
		g.Expect(tw.WriteHeader(&tar.Header{
			Name: f.name, Size: int64(len(f.content)), Mode: f.mode,
		})).To(Succeed())
		_, err := tw.Write([]byte(f.content))
		g.Expect(err).NotTo(HaveOccurred())
	}
	g.Expect(tw.Close()).To(Succeed())

	var zbuf bytes.Buffer
	zw, err := zstd.NewWriter(&zbuf)
	g.Expect(err).NotTo(HaveOccurred())
	_, err = zw.Write(raw.Bytes())
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(zw.Close()).To(Succeed())
	return zbuf.Bytes()
}

var _ = Describe("real install", func() {
	It("rejects an unsigned artifact", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		repoDir := t.TempDir()
		pkg := buildHelloPackage(t)
		Expect(os.WriteFile(filepath.Join(repoDir, "hello-1.0.0.tar.zst"), pkg, 0o644)).To(Succeed())
		// Deliberately publish NO .minisig for the artifact.
		anchor := newMinisignKeypair(t)
		signer := newMinisignKeypair(t)
		publishTrustDoc(t, repoDir, "native", anchor, 1,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
		publishIndex(t, repoDir, signer, 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		trustRoot := writeTrustRoot(t, anchor)
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(installHelloProfile(t, srv.URL, trustRoot)), 0o644)).To(Succeed())

		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"apply", profilePath})
		Expect(cmd.Execute()).To(HaveOccurred(), "apply must refuse an artifact with no signature")

		dataHome := os.Getenv("XDG_DATA_HOME")
		_, statErr := os.Lstat(filepath.Join(dataHome, "polypkg", "active"))
		Expect(statErr).To(HaveOccurred(), "no generation may be activated when verification fails")
	})

	It("rejects a signature from an untrusted key", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		pkg := buildHelloPackage(t)
		repoDir := t.TempDir()
		Expect(os.WriteFile(filepath.Join(repoDir, "hello-1.0.0.tar.zst"), pkg, 0o644)).To(Succeed())

		// Sign with one key but trust a DIFFERENT key: a valid-looking signature
		// that must fail cryptographic verification (not merely a presence check).
		signer := newMinisignKeypair(t) // signs the artifact but is NOT trusted
		Expect(os.WriteFile(filepath.Join(repoDir, "hello-1.0.0.tar.zst.minisig"),
			[]byte(signer.signArtifact("hello", "1.0.0", pkg)), 0o644)).To(Succeed())
		anchor := newMinisignKeypair(t)
		trusted := newMinisignKeypair(t)
		publishTrustDoc(t, repoDir, "native", anchor, 1,
			[]trustKeySpec{{kp: trusted, roles: []string{"index", "artifact"}}}, nil)
		publishIndex(t, repoDir, trusted, 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		trustRoot := writeTrustRoot(t, anchor)
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(installHelloProfile(t, srv.URL, trustRoot)), 0o644)).To(Succeed())

		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"apply", profilePath})
		Expect(cmd.Execute()).To(HaveOccurred(), "apply must reject a signature from an untrusted key")

		dataHome := os.Getenv("XDG_DATA_HOME")
		_, statErr := os.Lstat(filepath.Join(dataHome, "polypkg", "active"))
		Expect(statErr).To(HaveOccurred(), "no generation may be activated when verification fails")
	})

	It("installs the hello package and places the symlink in the active root", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		pkg := buildHelloPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(installHelloProfile(t, srv.URL, trustRoot)), 0o644)).To(Succeed())

		apply := cli.NewRootCmd()
		var out bytes.Buffer
		apply.SetOut(&out)
		apply.SetArgs([]string{"apply", profilePath})
		Expect(apply.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("applied generation"))

		dataHome := os.Getenv("XDG_DATA_HOME")
		hiPath := filepath.Join(dataHome, "polypkg", "active", "hello", "bin", "hi")
		info, err := os.Lstat(hiPath)
		Expect(err).NotTo(HaveOccurred(), "expected hello/bin/hi to exist in active root")
		Expect(info.Mode()&os.ModeSymlink != 0).To(BeTrue(), "expected symlink (policy=symlink)")

		// Reading through the symlink should yield the script content.
		resolved, err := os.Readlink(hiPath)
		Expect(err).NotTo(HaveOccurred())
		scriptBytes, err := os.ReadFile(resolved)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(scriptBytes)).To(ContainSubstring("hello from polypkg"))
	})
})
