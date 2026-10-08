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

// pkgExposingCmd builds a package named `name` that installs a tiny shipped
// script into its own namespace (<ActiveRoot>/<name>/bin/<cmd>) and then
// exposes it on the shared bin directory as command `cmd` via the path action.
// install runs in pre-place so the link target exists before path runs in
// post-place. The install param shape (src/dest/policy=symlink) and the path
// param shape (name/source) mirror the existing package builders.
func pkgExposingCmd(t testing.TB, name, cmd string) []byte {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: " + name + "\nversion: 1.0.0\nactions:\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/" + cmd +
		", dest: $ACTIVE/" + name + "/bin/" + cmd + ", policy: symlink}\n" +
		"  - phase: post-place\n    action: path\n    params: {name: " + cmd +
		", source: $ACTIVE/" + name + "/bin/" + cmd + "}\n"
	return buildTarZst(t, map[string]string{"polypkg.yaml": manifest, cmd: "#!/bin/sh\necho hi\n"})
}

// multiPackageProfile renders a polypkg.spec/v1 profile that requests each of
// the given package names (all pinned to =1.0.0) from the native source. It
// reuses the install-hello fixture's scopes/sources header (substituting the
// repo URL and trust root) and replaces the single-package packages block with
// one entry per name, so the resolver pulls every named artifact.
func multiPackageProfile(t testing.TB, repoURL, trustRoot string, names ...string) string {
	t.Helper()
	g := NewWithT(t)
	base := installHelloProfile(t, repoURL, trustRoot)
	idx := strings.Index(base, "packages:")
	g.Expect(idx).To(BeNumerically(">", 0), "fixture must contain a packages block")
	var b strings.Builder
	b.WriteString(base[:idx])
	b.WriteString("packages:\n  user:\n")
	for _, n := range names {
		fmt.Fprintf(&b, "    %s:\n      version: \"=1.0.0\"\n", n)
	}
	return b.String()
}

// applyProfileWith writes a multi-package profile naming the given packages and
// runs `apply` in-process via the real root command, returning the combined
// stdout+stderr and the execute error.
func applyProfileWith(t testing.TB, repoURL, trustRoot string, names ...string) (string, error) {
	t.Helper()
	g := NewWithT(t)
	profilePath := filepath.Join(t.TempDir(), "multi-profile.yaml")
	g.Expect(os.WriteFile(profilePath, []byte(multiPackageProfile(t, repoURL, trustRoot, names...)), 0o644)).To(Succeed())
	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"apply", profilePath})
	err := cmd.Execute()
	return out.String(), err
}

// planProfileWith writes a multi-package profile naming the given packages and
// runs `plan` in-process via the real root command, returning the combined
// output and the execute error.
func planProfileWith(t testing.TB, repoURL, trustRoot string, names ...string) (string, error) {
	t.Helper()
	g := NewWithT(t)
	profilePath := filepath.Join(t.TempDir(), "multi-plan-profile.yaml")
	g.Expect(os.WriteFile(profilePath, []byte(multiPackageProfile(t, repoURL, trustRoot, names...)), 0o644)).To(Succeed())
	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"plan", profilePath})
	err := cmd.Execute()
	return out.String(), err
}

var _ = Describe("path action and shared-path conflict e2e", func() {
	// binLink resolves a command's shared symlink in the active generation's
	// shared bin directory (<XDG_DATA_HOME>/polypkg/active/bin/<cmd>), reached
	// through the `active` generation symlink that apply swaps on commit.
	binLink := func(cmd string) string {
		return filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "active", "bin", cmd)
	}

	It("scenario 1: a single package's path action places a resolvable shared symlink", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		// applyHelloOnce drives the install-hello fixture, which pins
		// packages.user.hello; the exposing package is therefore named hello.
		pkg := pkgExposingCmd(t, "hello", "greet")
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		out, err := applyHelloOnce(t, srv.URL, trust)
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)
		// The shared link exists and points into the package's own namespace.
		target, rerr := os.Readlink(binLink("greet"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(target).To(ContainSubstring(filepath.Join("hello", "bin", "greet")))
	})

	It("scenario 2: two packages exposing the same command refuse the apply", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		a := pkgExposingCmd(t, "alpha", "greet")
		b := pkgExposingCmd(t, "bravo", "greet")
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "alpha", version: "1.0.0", artifact: a},
			indexPkg{name: "bravo", version: "1.0.0", artifact: b})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		out, err := applyProfileWith(t, srv.URL, trust, "alpha", "bravo")
		Expect(err).To(HaveOccurred())
		Expect(err.Error() + out).To(ContainSubstring("conflict"))
		// The conflict check runs before the swap, so no generation is
		// committed: the active symlink (and thus the shared command link) is
		// never created.
		_, statErr := os.Lstat(binLink("greet"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
	})

	It("scenario 3: plan reports the shared-path conflict as an error", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		a := pkgExposingCmd(t, "alpha", "greet")
		b := pkgExposingCmd(t, "bravo", "greet")
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "alpha", version: "1.0.0", artifact: a},
			indexPkg{name: "bravo", version: "1.0.0", artifact: b})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		out, err := planProfileWith(t, srv.URL, trust, "alpha", "bravo")
		Expect(err).To(HaveOccurred())
		Expect(err.Error() + out).To(ContainSubstring("conflict"))
	})

	It("scenario 4: a package named bin is rejected for the reserved shared-directory name", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := pkgExposingCmd(t, "bin", "greet")
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1, indexPkg{name: "bin", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		out, err := applyProfileWith(t, srv.URL, trust, "bin")
		Expect(err).To(HaveOccurred())
		Expect(err.Error() + out).To(ContainSubstring("reserved"))
	})
})
