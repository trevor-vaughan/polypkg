package integration

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// pkgShippingCompletions builds a package "tool" that installs a completion
// script per shell into its own namespace and declares a completion action for
// each shell, all for command name "tool".
func pkgShippingCompletions(t testing.TB) []byte {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: tool\nversion: 1.0.0\nactions:\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/tool.bash, dest: $ACTIVE/tool/comp/tool.bash, policy: symlink}\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/tool.zsh, dest: $ACTIVE/tool/comp/tool.zsh, policy: symlink}\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/tool.fish, dest: $ACTIVE/tool/comp/tool.fish, policy: symlink}\n" +
		"  - phase: post-place\n    action: completion\n    params: {shell: bash, name: tool, source: $ACTIVE/tool/comp/tool.bash}\n" +
		"  - phase: post-place\n    action: completion\n    params: {shell: zsh, name: tool, source: $ACTIVE/tool/comp/tool.zsh}\n" +
		"  - phase: post-place\n    action: completion\n    params: {shell: fish, name: tool, source: $ACTIVE/tool/comp/tool.fish}\n"
	return buildTarZst(t, map[string]string{
		"polypkg.yaml": manifest,
		"tool.bash":    "# bash completion\n",
		"tool.zsh":     "# zsh completion\n",
		"tool.fish":    "# fish completion\n",
	})
}

var _ = Describe("completion install e2e", func() {
	// dataHome returns the polypkg data dir inside the isolated XDG_DATA_HOME.
	dataHome := func() string { return filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg") }

	// bashHost is bash-completion's user dir (XDG_DATA_HOME/bash-completion/completions).
	bashHost := func() string {
		return filepath.Join(os.Getenv("XDG_DATA_HOME"), "bash-completion", "completions")
	}
	// zshHost is the user zsh site-functions dir (XDG_DATA_HOME/zsh/site-functions).
	zshHost := func() string {
		return filepath.Join(os.Getenv("XDG_DATA_HOME"), "zsh", "site-functions")
	}
	// fishHost is fish's user completions dir (XDG_CONFIG_HOME/fish/completions).
	fishHost := func() string {
		return filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "fish", "completions")
	}
	// activeComp is the active generation's shared completions area
	// (XDG_DATA_HOME/polypkg/active/completions).
	activeComp := func() string {
		return filepath.Join(dataHome(), "active", "completions")
	}

	It("installs per-shell completions on apply, is foreign-safe, and prunes on unlink", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := pkgShippingCompletions(t)
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1, indexPkg{name: "tool", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		// Pre-create a foreign bash completion to prove it is never clobbered.
		Expect(os.MkdirAll(bashHost(), 0o750)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(bashHost(), "foreign"), []byte("mine"), 0o644)).To(Succeed())

		// Apply installs all three shells' completions as symlinks into the active tree.
		out, err := applyProfileWith(t, srv.URL, trust, "tool")
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)

		// bash: symlink at bashHost/tool -> activeComp/bash/tool
		bashLink := filepath.Join(bashHost(), "tool")
		tgt, rerr := os.Readlink(bashLink)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(tgt).To(Equal(filepath.Join(activeComp(), "bash", "tool")))

		// zsh: symlink at zshHost/_tool
		_, statErr := os.Lstat(filepath.Join(zshHost(), "_tool"))
		Expect(statErr).NotTo(HaveOccurred())

		// fish: symlink at fishHost/tool.fish
		_, statErr = os.Lstat(filepath.Join(fishHost(), "tool.fish"))
		Expect(statErr).NotTo(HaveOccurred())

		// The pre-existing foreign file is untouched.
		b, readErr := os.ReadFile(filepath.Join(bashHost(), "foreign"))
		Expect(readErr).NotTo(HaveOccurred())
		Expect(string(b)).To(Equal("mine"))

		// unlink removes polypkg-owned completion links but leaves the foreign file.
		unlinkOut, unlinkErr := runUnlinkInProcess()
		Expect(unlinkErr).To(Succeed(), "unlink output: %s", unlinkOut)

		_, statErr = os.Lstat(bashLink)
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "bash completion link must be removed by unlink")

		_, statErr = os.Lstat(filepath.Join(fishHost(), "tool.fish"))
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "fish completion link must be removed by unlink")

		_, statErr = os.Lstat(filepath.Join(zshHost(), "_tool"))
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "zsh completion link must be removed by unlink")

		// The foreign file survives.
		_, statErr = os.Lstat(filepath.Join(bashHost(), "foreign"))
		Expect(statErr).NotTo(HaveOccurred(), "foreign file must survive unlink")
	})

	It("does not write into shell dirs when completion.enabled=false", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		t.Setenv("POLYPKG_COMPLETION_ENABLED", "false")
		pkg := pkgShippingCompletions(t)
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1, indexPkg{name: "tool", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		out, err := applyProfileWith(t, srv.URL, trust, "tool")
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)

		// With completion disabled, no host-shell symlinks should exist.
		_, statErr := os.Lstat(filepath.Join(bashHost(), "tool"))
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "bash host dir must not have a polypkg link when disabled")

		_, statErr = os.Lstat(filepath.Join(zshHost(), "_tool"))
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "zsh host dir must not have a polypkg link when disabled")

		_, statErr = os.Lstat(filepath.Join(fishHost(), "tool.fish"))
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "fish host dir must not have a polypkg link when disabled")
	})
})
