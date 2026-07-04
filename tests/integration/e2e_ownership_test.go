package integration

import (
	"archive/tar"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/cli"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// buildOwnershipPackage builds hello-1.0.0 with dir + install + symlink actions
// (post-place) and a perms action (pre-activate) re-chmod-ing the dir, so the
// committed ownership index has a path (hello/bin) owned by two actions.
func buildOwnershipPackage(t testing.TB) []byte {
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
  - phase: post-place
    action: symlink
    params:
      src: bin/hi
      dest: $ACTIVE/hello/bin/hi-link
  - phase: pre-activate
    action: perms
    params:
      path: $ACTIVE/hello/bin
      mode: "0o700"
`
	hi := "#!/bin/sh\necho hello from polypkg\n"

	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	files := []struct {
		name, content string
		mode          int64
	}{
		{"polypkg.yaml", manifest, 0o644},
		{"content/bin/hi", hi, 0o755},
	}
	for _, f := range files {
		g.Expect(tw.WriteHeader(&tar.Header{Name: f.name, Size: int64(len(f.content)), Mode: f.mode})).To(Succeed())
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

// buildUnhashableSourcePackage builds hello-1.0.0 whose install src points at a
// DIRECTORY ($PKG/content) rather than a regular file. The install action creates
// the symlink, then capture's hashSource opens the directory and fails on read --
// an injected capture failure mid-apply.
func buildUnhashableSourcePackage(t testing.TB) []byte {
	t.Helper()
	manifest := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: install
    params:
      src: $PKG/content
      dest: $ACTIVE/hello/data
      policy: symlink
`
	return buildTarZst(t, map[string]string{
		"polypkg.yaml":   manifest,
		"content/marker": "x",
	})
}

var _ = Describe("ownership index", func() {
	It("writes a complete ownership index for dir/install/symlink/perms actions", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		pkg := buildOwnershipPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(installHelloProfile(t, srv.URL, trustRoot)), 0o644)).To(Succeed())

		cmd := cli.NewRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"apply", profilePath})
		Expect(cmd.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("applied generation"))

		dataHome := os.Getenv("XDG_DATA_HOME")
		f, err := os.Open(filepath.Join(dataHome, "polypkg", "generations", "1", "ownership.json"))
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		own, err := schema.ParseOwnership(f)
		Expect(err).NotTo(HaveOccurred())

		Expect(own.Schema).To(Equal("polypkg.ownership/v1"))
		Expect(own.Scope).To(Equal("user"))

		type pv struct{ path, action string }
		got := map[pv]schema.OwnershipEntry{}
		for _, e := range own.Entries {
			got[pv{e.Path, e.Action}] = e
		}

		dirE, ok := got[pv{"hello/bin", "dir"}]
		Expect(ok).To(BeTrue(), "dir entry for hello/bin")
		Expect(dirE.Expected.FileType).To(Equal("dir"))

		hiE, ok := got[pv{"hello/bin/hi", "install"}]
		Expect(ok).To(BeTrue(), "install entry for hello/bin/hi")
		Expect(hiE.Expected.FileType).To(Equal("symlink"))
		Expect(strings.HasPrefix(hiE.Expected.ContentHash, "blake3:")).To(BeTrue())
		Expect(hiE.Stat.Inode).NotTo(BeZero())

		linkE, ok := got[pv{"hello/bin/hi-link", "symlink"}]
		Expect(ok).To(BeTrue(), "symlink entry for hello/bin/hi-link")
		Expect(linkE.Expected.Target).To(Equal("bin/hi"))

		permsE, ok := got[pv{"hello/bin", "perms"}]
		Expect(ok).To(BeTrue(), "perms entry re-owning hello/bin")
		Expect(permsE.Expected.Mode).To(ContainSubstring("700"))
	})

	It("aborts with no generation when a capture step fails mid-apply", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		pkg := buildUnhashableSourcePackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(installHelloProfile(t, srv.URL, trustRoot)), 0o644)).To(Succeed())

		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"apply", profilePath})
		Expect(cmd.Execute()).To(HaveOccurred(), "a capture failure mid-apply must fail the apply")

		// Fail-closed: no generation is activated and the staged generation is gone,
		// so a committed ownership index is never incomplete.
		dataHome := os.Getenv("XDG_DATA_HOME")
		_, err := os.Lstat(filepath.Join(dataHome, "polypkg", "active"))
		Expect(err).To(HaveOccurred(), "no generation may be activated when capture fails")
		_, err = os.Stat(filepath.Join(dataHome, "polypkg", "generations", "1"))
		Expect(err).To(HaveOccurred(), "the staged generation must be removed on abort")
	})
})
