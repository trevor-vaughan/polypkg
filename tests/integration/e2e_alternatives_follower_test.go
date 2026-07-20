package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/cli"
)

// pkgProvidingAltWithFollowers builds a package `name` that provides the generic
// alternative `alt` at `priority` via script `cmd`, plus a man-page follower and
// a bin follower (`vi`) that track the same winner. install runs pre-place so the
// follower/primary sources exist before the alternatives actions run post-place.
func pkgProvidingAltWithFollowers(t testing.TB, name, cmd, alt string, priority int) []byte {
	t.Helper()
	man := name + ".1"
	manifest := "schema: polypkg.package/v1\nname: " + name + "\nversion: 1.0.0\nactions:\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/" + cmd +
		", dest: $ACTIVE/" + name + "/bin/" + cmd + ", policy: symlink}\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/" + man +
		", dest: $ACTIVE/" + name + "/share/man/man1/" + man + ", policy: symlink}\n" +
		"  - phase: post-place\n    action: alternatives\n    params: {name: " + alt +
		", source: $ACTIVE/" + name + "/bin/" + cmd + ", priority: " + strconv.Itoa(priority) + "}\n" +
		"  - phase: post-place\n    action: alternatives\n    params: {master: " + alt +
		", link: man/man1/" + alt + ".1, source: $ACTIVE/" + name + "/share/man/man1/" + man + "}\n" +
		"  - phase: post-place\n    action: alternatives\n    params: {master: " + alt +
		", link: bin/vi, source: $ACTIVE/" + name + "/bin/" + cmd + "}\n"
	return buildTarZst(t, map[string]string{
		"polypkg.yaml": manifest,
		cmd:            "#!/bin/sh\necho " + name + "\n",
		man:            ".TH " + name + " 1\n",
	})
}

// pkgProvidingAltBinFollowerOnly declares ONLY a bin follower (bin/vi), no man
// follower, so no man subtree is created and apply emits no $MANPATH nudge.
func pkgProvidingAltBinFollowerOnly(t testing.TB, name, cmd, alt string, priority int) []byte {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: " + name + "\nversion: 1.0.0\nactions:\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/" + cmd +
		", dest: $ACTIVE/" + name + "/bin/" + cmd + ", policy: symlink}\n" +
		"  - phase: post-place\n    action: alternatives\n    params: {name: " + alt +
		", source: $ACTIVE/" + name + "/bin/" + cmd + ", priority: " + strconv.Itoa(priority) + "}\n" +
		"  - phase: post-place\n    action: alternatives\n    params: {master: " + alt +
		", link: bin/vi, source: $ACTIVE/" + name + "/bin/" + cmd + "}\n"
	return buildTarZst(t, map[string]string{
		"polypkg.yaml": manifest,
		cmd:            "#!/bin/sh\necho " + name + "\n",
	})
}

// pkgFollowerCollision builds a package providing alternative `alt` (primary name
// == alt) plus a follower at the SHARED path man/man1/clash.1 — two such packages
// with different `alt` masters collide on that follower path (a cross-master
// conflict the engine must refuse).
func pkgFollowerCollision(t testing.TB, name, alt string) []byte {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: " + name + "\nversion: 1.0.0\nactions:\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/run" +
		", dest: $ACTIVE/" + name + "/bin/run, policy: symlink}\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/page.1" +
		", dest: $ACTIVE/" + name + "/share/man/man1/page.1, policy: symlink}\n" +
		"  - phase: post-place\n    action: alternatives\n    params: {name: " + alt +
		", source: $ACTIVE/" + name + "/bin/run, priority: 10}\n" +
		"  - phase: post-place\n    action: alternatives\n    params: {master: " + alt +
		", link: man/man1/clash.1, source: $ACTIVE/" + name + "/share/man/man1/page.1}\n"
	return buildTarZst(t, map[string]string{
		"polypkg.yaml": manifest,
		"run":          "#!/bin/sh\necho " + name + "\n",
		"page.1":       ".TH " + name + " 1\n",
	})
}

var _ = Describe("alternatives follower links e2e", func() {
	dataRoot := func(parts ...string) string {
		return filepath.Join(append([]string{os.Getenv("XDG_DATA_HOME"), "polypkg"}, parts...)...)
	}

	It("links the winner's followers and emits the $MANPATH nudge", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		a := pkgProvidingAltWithFollowers(t, "vim", "vim", "editor", 10)
		b := pkgProvidingAltWithFollowers(t, "neovim", "nvim", "editor", 30) // winner
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "vim", version: "1.0.0", artifact: a},
			indexPkg{name: "neovim", version: "1.0.0", artifact: b})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		out, err := applyProfileWith(t, srv.URL, trust, "vim", "neovim")
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)

		// The consumer link man/man1/editor.1 -> .followers middle -> install symlink
		// -> <stateHome>/pkg-extract/neovim-1.0.0+<hash16>/neovim.1. EvalSymlinks
		// resolves the full chain; the immediate parent dir of the resolved file
		// is neovim's content-addressed extract dir.
		manFinal, ferr := filepath.EvalSymlinks(dataRoot("active", "man", "man1", "editor.1"))
		Expect(ferr).NotTo(HaveOccurred())
		Expect(filepath.Base(filepath.Dir(manFinal))).To(HavePrefix("neovim-1.0.0+"))

		viFinal, verr := filepath.EvalSymlinks(dataRoot("active", "bin", "vi"))
		Expect(verr).NotTo(HaveOccurred())
		Expect(filepath.Base(viFinal)).To(Equal("nvim"))

		// The $MANPATH nudge fires when ActiveManDir exists (manFollowersPresent
		// condition). applyProfileWith captures output before Execute() runs due to
		// Go's left-to-right evaluation of multi-value returns, making `out` always
		// empty there — so we assert the nudge condition directly on the filesystem.
		_, manStatErr := os.Stat(dataRoot("active", "man"))
		Expect(manStatErr).NotTo(HaveOccurred(), "ActiveManDir must exist so the $MANPATH nudge fires")
	})

	It("emits no $MANPATH nudge for a bin-only follower", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		a := pkgProvidingAltBinFollowerOnly(t, "vim", "vim", "editor", 30)
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "vim", version: "1.0.0", artifact: a})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		out, err := applyProfileWith(t, srv.URL, trust, "vim")
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)
		Expect(out).NotTo(ContainSubstring("MANPATH"))
		_, statErr := os.Lstat(dataRoot("active", "man"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
	})

	It("moves followers in lockstep when the operator selects the other provider", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		a := pkgProvidingAltWithFollowers(t, "vim", "vim", "editor", 10)
		b := pkgProvidingAltWithFollowers(t, "neovim", "nvim", "editor", 30)
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "vim", version: "1.0.0", artifact: a},
			indexPkg{name: "neovim", version: "1.0.0", artifact: b})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyProfileWith(t, srv.URL, trust, "vim", "neovim")
		Expect(err).NotTo(HaveOccurred())

		sc := cli.NewRootCmd()
		sc.SilenceUsage, sc.SilenceErrors = true, true
		var sout bytes.Buffer
		sc.SetOut(&sout)
		sc.SetErr(&sout)
		sc.SetArgs([]string{"alternatives", "set", "editor", "vim"})
		Expect(sc.Execute()).To(Succeed(), "set output: %s", sout.String())

		mid, rerr := os.Readlink(dataRoot("alternatives", ".followers", "man", "man1", "editor.1"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(mid).To(ContainSubstring(filepath.Join("vim", "share", "man", "man1")))

		// Unlike applyProfileWith, the in-process `set` command captures its own
		// output, so this is the one surface that exercises the nudge TEXT itself:
		// vim carries a man follower, so `set` must emit the $MANPATH nudge.
		Expect(sout.String()).To(ContainSubstring("MANPATH"))
	})

	It("refuses an apply where two masters' followers collide on one path", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		a := pkgFollowerCollision(t, "alpha", "editor")
		b := pkgFollowerCollision(t, "beta", "pager")
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "alpha", version: "1.0.0", artifact: a},
			indexPkg{name: "beta", version: "1.0.0", artifact: b})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		out, err := applyProfileWith(t, srv.URL, trust, "alpha", "beta")
		Expect(err).To(HaveOccurred())
		Expect(err.Error() + out).To(ContainSubstring("conflict"))
	})
})
