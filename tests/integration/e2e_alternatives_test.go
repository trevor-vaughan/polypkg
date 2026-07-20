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

	"github.com/trevor-vaughan/polypkg/internal/alternatives"
	"github.com/trevor-vaughan/polypkg/internal/cli"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// pkgProvidingAlt builds a package `name` that installs a script `cmd` and
// registers it as a provider of the generic alternative `alt` at `priority`.
// install runs in pre-place so the link target exists before the alternatives
// action runs in post-place; the install param shape (src/dest/policy=symlink)
// mirrors pkgExposingCmd. The integer priority renders as a bare YAML number.
func pkgProvidingAlt(t testing.TB, name, cmd, alt string, priority int) []byte {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: " + name + "\nversion: 1.0.0\nactions:\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/" + cmd +
		", dest: $ACTIVE/" + name + "/bin/" + cmd + ", policy: symlink}\n" +
		"  - phase: post-place\n    action: alternatives\n    params: {name: " + alt +
		", source: $ACTIVE/" + name + "/bin/" + cmd + ", priority: " + strconv.Itoa(priority) + "}\n"
	return buildTarZst(t, map[string]string{"polypkg.yaml": manifest, cmd: "#!/bin/sh\necho " + name + "\n"})
}

var _ = Describe("alternatives action arbitration e2e", func() {
	// altMid resolves an alternative's stable middle link in the substrate's
	// non-generational alternatives area. apply uses paths.UserDataHome() +
	// substrate.NewOwnStore, so AltRoot() == <XDG_DATA_HOME>/polypkg/alternatives.
	altMid := func(alt string) string {
		return filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "alternatives", alt)
	}
	// binLink resolves a command's consumer link in the active generation's
	// shared bin directory (<XDG_DATA_HOME>/polypkg/active/bin/<cmd>).
	binLink := func(cmd string) string {
		return filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "active", "bin", cmd)
	}

	It("auto-arbitrates the highest-priority provider", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		a := pkgProvidingAlt(t, "vim", "vim", "editor", 10)
		b := pkgProvidingAlt(t, "neovim", "nvim", "editor", 30)
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "vim", version: "1.0.0", artifact: a},
			indexPkg{name: "neovim", version: "1.0.0", artifact: b})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		out, err := applyProfileWith(t, srv.URL, trust, "vim", "neovim")
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)

		// Middle link points at the priority-30 winner's source.
		midTarget, rerr := os.Readlink(altMid("editor"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(midTarget).To(ContainSubstring(filepath.Join("neovim", "bin", "nvim")))

		// The consumer link resolves through the middle link end-to-end. install
		// places $ACTIVE/<pkg>/bin/<cmd> as a symlink into the package's extract
		// dir, so the fully-resolved path lands on neovim's real script
		// (.../pkg-extract/neovim-1.0.0+<hash16>/nvim), not vim's — proving the
		// winner resolves all the way to its own artifact.
		final, ferr := filepath.EvalSymlinks(binLink("editor"))
		Expect(ferr).NotTo(HaveOccurred())
		Expect(filepath.Base(filepath.Dir(final))).To(HavePrefix("neovim-1.0.0+")) // winner's extract dir
		Expect(filepath.Base(final)).To(Equal("nvim"))                             // winner's script, not vim's
	})

	It("refuses an apply mixing a path provider and an alternatives provider", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		a := pkgExposingCmd(t, "vim", "editor")                 // path-exposes bin/editor
		b := pkgProvidingAlt(t, "neovim", "nvim", "editor", 30) // alternatives-registers editor
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "vim", version: "1.0.0", artifact: a},
			indexPkg{name: "neovim", version: "1.0.0", artifact: b})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		out, err := applyProfileWith(t, srv.URL, trust, "vim", "neovim")
		Expect(err).To(HaveOccurred())
		Expect(err.Error() + out).To(ContainSubstring("conflict"))
		// Refused before the swap: nothing committed for either link.
		_, statErr := os.Lstat(binLink("editor"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
		_, midErr := os.Lstat(altMid("editor"))
		Expect(os.IsNotExist(midErr)).To(BeTrue())
	})

	It("refuses an apply where two packages path-expose the same command (regression)", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		a := pkgExposingCmd(t, "vim", "editor")
		b := pkgExposingCmd(t, "neovim", "editor")
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "vim", version: "1.0.0", artifact: a},
			indexPkg{name: "neovim", version: "1.0.0", artifact: b})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		out, err := applyProfileWith(t, srv.URL, trust, "vim", "neovim")
		Expect(err).To(HaveOccurred())
		Expect(err.Error() + out).To(ContainSubstring("conflict"))
		_, statErr := os.Lstat(binLink("editor"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
	})

	It("re-points the middle link to the rolled-back generation's winner", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		a := pkgProvidingAlt(t, "vim", "vim", "editor", 10)
		b := pkgProvidingAlt(t, "neovim", "nvim", "editor", 30)
		repoDir := t.TempDir()
		// Both artifacts are indexed; each generation requests a different subset.
		trust := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "vim", version: "1.0.0", artifact: a},
			indexPkg{name: "neovim", version: "1.0.0", artifact: b})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		// gen1: only vim provides editor -> vim wins.
		out1, err := applyProfileWith(t, srv.URL, trust, "vim")
		Expect(err).NotTo(HaveOccurred(), "gen1 apply output: %s", out1)
		mid1, rerr := os.Readlink(altMid("editor"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(mid1).To(ContainSubstring(filepath.Join("vim", "bin", "vim")))

		// gen2: add neovim at priority 30 -> neovim wins.
		out2, err := applyProfileWith(t, srv.URL, trust, "vim", "neovim")
		Expect(err).NotTo(HaveOccurred(), "gen2 apply output: %s", out2)
		mid2, rerr := os.Readlink(altMid("editor"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(mid2).To(ContainSubstring(filepath.Join("neovim", "bin", "nvim")))

		// Roll back to gen1: rollback reconciles alternatives to the now-active
		// generation, which only contains vim, so the middle link must re-point
		// to vim and never resolve through neovim (absent in gen1).
		rb := cli.NewRootCmd()
		rb.SilenceUsage, rb.SilenceErrors = true, true
		var rout bytes.Buffer
		rb.SetOut(&rout)
		rb.SetErr(&rout)
		rb.SetArgs([]string{"rollback"})
		Expect(rb.Execute()).To(Succeed(), "rollback output: %s", rout.String())

		mid3, rerr := os.Readlink(altMid("editor"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(mid3).To(ContainSubstring(filepath.Join("vim", "bin", "vim")))
		Expect(mid3).NotTo(ContainSubstring("neovim"))
	})

	// System-scope coverage: the apply CLI is hardcoded to the "user" scope
	// (apply.go reads p.Scopes["user"] and passes Scope:"user"), so the
	// integration harness cannot drive a system-scope apply end to end. The
	// scope boundary that matters for alternatives is the per-scope AltRoot():
	// each scope materializes its winners into its own substrate's alternatives
	// area, with no shared mutable state. Two independent substrate roots model
	// the user vs system scopes exactly, so we assert scope independence at the
	// substrate/alternatives boundary. (Harness gap noted as a follow-up.)
	It("materializes scope-independent winners across distinct substrate roots", func() {
		t := GinkgoTB()
		userRoot := t.TempDir()
		sysRoot := t.TempDir()
		userSub, err := substrate.NewOwnStore(userRoot)
		Expect(err).NotTo(HaveOccurred())
		sysSub, err := substrate.NewOwnStore(sysRoot)
		Expect(err).NotTo(HaveOccurred())

		// editor entries shaped exactly as the alternatives action records them
		// (Action=alternatives, Path=bin/<name>, Expected.Target=source, Priority).
		mkEntry := func(pkg, source string, priority int) schema.OwnershipEntry {
			return schema.OwnershipEntry{
				Path: "bin/editor", Package: pkg, Action: "alternatives",
				Expected: schema.Expected{FileType: "symlink", Target: source, Priority: priority},
			}
		}
		// User scope: vim(10) vs neovim(30) -> neovim wins.
		userEntries := []schema.OwnershipEntry{
			mkEntry("vim", filepath.Join(userRoot, "active", "vim", "bin", "vim"), 10),
			mkEntry("neovim", filepath.Join(userRoot, "active", "neovim", "bin", "nvim"), 30),
		}
		// System scope: vim(40) vs neovim(30) -> vim wins (different winner).
		sysEntries := []schema.OwnershipEntry{
			mkEntry("vim", filepath.Join(sysRoot, "active", "vim", "bin", "vim"), 40),
			mkEntry("neovim", filepath.Join(sysRoot, "active", "neovim", "bin", "nvim"), 30),
		}

		_, err = alternatives.Reconcile(userSub.AltRoot(), filepath.Join(t.TempDir(), "absent.json"), userEntries)
		Expect(err).NotTo(HaveOccurred())
		_, err = alternatives.Reconcile(sysSub.AltRoot(), filepath.Join(t.TempDir(), "absent.json"), sysEntries)
		Expect(err).NotTo(HaveOccurred())

		userMid, uerr := os.Readlink(filepath.Join(userSub.AltRoot(), "editor"))
		Expect(uerr).NotTo(HaveOccurred())
		Expect(userMid).To(ContainSubstring(filepath.Join("neovim", "bin", "nvim")))

		sysMid, serr := os.Readlink(filepath.Join(sysSub.AltRoot(), "editor"))
		Expect(serr).NotTo(HaveOccurred())
		Expect(sysMid).To(ContainSubstring(filepath.Join("vim", "bin", "vim")))

		// Each scope's middle link is anchored under its own root: neither leaks
		// into the other, and the user re-materialize did not touch the system
		// area's winner (distinct winners prove the roots are independent).
		Expect(userMid).To(HavePrefix(userRoot))
		Expect(sysMid).To(HavePrefix(sysRoot))
	})
})
