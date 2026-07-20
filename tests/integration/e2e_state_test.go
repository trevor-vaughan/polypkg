package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"

	"github.com/trevor-vaughan/polypkg/internal/cli"
)

// helloStatePackage declares a single `state` directory under the active tree.
func helloStatePackage(t testing.TB, version string) []byte {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: hello\nversion: " + version + "\nactions:\n" +
		"  - phase: post-place\n    action: state\n    params: {path: $ACTIVE/hello/var/lib/app}\n"
	return buildTarZst(t, map[string]string{"polypkg.yaml": manifest})
}

// helloGhostPackage declares a single `unmanaged` path. The action records a
// ghost ownership entry and creates nothing on disk.
func helloGhostPackage(t testing.TB) []byte {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions:\n" +
		"  - phase: post-place\n    action: unmanaged\n    params: {path: $ACTIVE/hello/var/run/app.sock}\n"
	return buildTarZst(t, map[string]string{"polypkg.yaml": manifest})
}

// applyEmptyProfile applies a profile that resolves to zero packages, producing
// a new generation with no hello artifacts. The planner's no-package path
// commits an empty generation, so the active symlink swaps and hello's
// active-tree entries disappear while the stable state area is untouched.
func applyEmptyProfile(t testing.TB) {
	t.Helper()
	g := NewWithT(t)
	// Reuse the install-hello scopes/sources block but drop the packages map.
	// installHelloProfile substitutes a repo URL and trust root; for an empty
	// profile no source is consulted, so placeholder values are harmless.
	base := installHelloProfile(t, "http://127.0.0.1:0", "/dev/null")
	idx := strings.Index(base, "packages:")
	g.Expect(idx).To(BeNumerically(">", 0), "fixture must contain a packages block")
	profile := base[:idx]
	profilePath := filepath.Join(t.TempDir(), "empty-profile.yaml")
	g.Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())

	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"apply", profilePath})
	g.Expect(cmd.Execute()).To(Succeed())
}

// applyHelloStateV2 re-signs the repo at serial 2 with a v2 state package
// (same state path) and applies it, mirroring applyHelloV2 from the config
// suite.
func applyHelloStateV2(t testing.TB, repoDir, repoURL string) error {
	t.Helper()
	v2pkg := helloStatePackage(t, "2.0.0")
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

func purgeCmd(args ...string) *cobra.Command {
	root := cli.NewRootCmd()
	root.SilenceUsage, root.SilenceErrors = true, true
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(append([]string{"purge"}, args...))
	return root
}

var _ = Describe("state and unmanaged e2e", func() {
	// stableStateDir is the persistent state directory the `state` action manages,
	// at <XDG_DATA_HOME>/polypkg/state/<pkg>/<rel>. It is never swapped and only
	// `polypkg purge` deletes it.
	stableStateDir := func() string {
		return filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "state", "hello", "var", "lib", "app")
	}
	// livePath resolves a path inside the active tree
	// (<XDG_DATA_HOME>/polypkg/active/hello/...), reached through the `active`
	// generation symlink.
	livePath := func(rel ...string) string {
		parts := append([]string{os.Getenv("XDG_DATA_HOME"), "polypkg", "active", "hello"}, rel...)
		return filepath.Join(parts...)
	}

	It("scenario 1: state persists across re-apply", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloStatePackage(t, "1.0.0")
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHelloOnce(t, srv.URL, trust)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(livePath("var", "lib", "app", "db"), []byte("data"), 0o600)).To(Succeed())
		_, err = applyHelloOnce(t, srv.URL, trust)
		Expect(err).NotTo(HaveOccurred())
		got, err := os.ReadFile(filepath.Join(stableStateDir(), "db"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("data"))
	})

	It("scenario 2: state survives package removal", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloStatePackage(t, "1.0.0")
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHelloOnce(t, srv.URL, trust)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(livePath("var", "lib", "app", "db"), []byte("data"), 0o600)).To(Succeed())

		// Remove hello by applying a profile with zero packages.
		applyEmptyProfile(t)

		// The active-tree symlink is gone with the swapped-out generation.
		_, statErr := os.Lstat(livePath("var", "lib", "app"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
		// The stable state dir and its file survive the removal.
		got, err := os.ReadFile(filepath.Join(stableStateDir(), "db"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("data"))
	})

	It("scenario 3: state survives rollback", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloStatePackage(t, "1.0.0")
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHelloOnce(t, srv.URL, trust) // gen 1, v1.0.0
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(livePath("var", "lib", "app", "db"), []byte("data"), 0o600)).To(Succeed())

		err = applyHelloStateV2(t, repoDir, srv.URL) // gen 2, v2.0.0
		Expect(err).NotTo(HaveOccurred())

		// Roll back to the previous generation.
		rb := cli.NewRootCmd()
		rb.SilenceUsage, rb.SilenceErrors = true, true
		rb.SetOut(&bytes.Buffer{})
		rb.SetErr(&bytes.Buffer{})
		rb.SetArgs([]string{"rollback"})
		Expect(rb.Execute()).To(Succeed())

		// The stable state file is still present after rollback.
		got, err := os.ReadFile(filepath.Join(stableStateDir(), "db"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("data"))
	})

	It("scenario 4+5: purge deletes orphaned state and refuses an active package", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloStatePackage(t, "1.0.0")
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHelloOnce(t, srv.URL, trust)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.MkdirAll(stableStateDir(), 0o700)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(stableStateDir(), "db"), []byte("data"), 0o600)).To(Succeed())

		refuse := purgeCmd("hello")
		Expect(refuse.Execute()).NotTo(Succeed())
		_, statErr := os.Stat(stableStateDir())
		Expect(statErr).NotTo(HaveOccurred()) // state untouched

		applyEmptyProfile(t)
		_, statErr = os.Lstat(livePath("var", "lib", "app"))
		Expect(os.IsNotExist(statErr)).To(BeTrue()) // active-tree symlink gone
		_, statErr = os.Stat(stableStateDir())
		Expect(statErr).NotTo(HaveOccurred()) // stable state preserved

		ok := purgeCmd("hello", "--yes")
		Expect(ok.Execute()).To(Succeed())
		_, statErr = os.Stat(filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "state", "hello"))
		Expect(os.IsNotExist(statErr)).To(BeTrue()) // purged
	})

	It("scenario 6: unmanaged is recorded and never drift", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloGhostPackage(t)
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHelloOnce(t, srv.URL, trust)
		Expect(err).NotTo(HaveOccurred())
		_, statErr := os.Lstat(livePath("var", "run", "app.sock"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
		Expect(os.MkdirAll(livePath("var", "run"), 0o755)).To(Succeed())
		Expect(os.WriteFile(livePath("var", "run", "app.sock"), []byte("x"), 0o600)).To(Succeed())
		out, err := applyHelloOnce(t, srv.URL, trust)
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("applied generation"))
	})
})
