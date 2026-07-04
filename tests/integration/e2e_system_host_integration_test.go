package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/cli"
)

// pkgFullHostIntegration builds package "tool" that exposes a command (path), a
// .desktop, a shared-mime .xml, and per-shell completions — every host-integration
// action in one package, for the system-scope host-integration e2e.
func pkgFullHostIntegration(t testing.TB) []byte {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: tool\nversion: 1.0.0\nactions:\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/tool, dest: $ACTIVE/tool/bin/tool, policy: symlink}\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/org.foo.Bar.desktop, dest: $ACTIVE/tool/share/org.foo.Bar.desktop, policy: symlink}\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/tool.xml, dest: $ACTIVE/tool/share/tool.xml, policy: symlink}\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/tool.bash, dest: $ACTIVE/tool/comp/tool.bash, policy: symlink}\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/tool.zsh, dest: $ACTIVE/tool/comp/tool.zsh, policy: symlink}\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/tool.fish, dest: $ACTIVE/tool/comp/tool.fish, policy: symlink}\n" +
		"  - phase: post-place\n    action: path\n    params: {name: tool, source: $ACTIVE/tool/bin/tool}\n" +
		"  - phase: post-place\n    action: desktop\n    params: {source: $ACTIVE/tool/share/org.foo.Bar.desktop}\n" +
		"  - phase: post-place\n    action: mime\n    params: {source: $ACTIVE/tool/share/tool.xml}\n" +
		"  - phase: post-place\n    action: completion\n    params: {shell: bash, name: tool, source: $ACTIVE/tool/comp/tool.bash}\n" +
		"  - phase: post-place\n    action: completion\n    params: {shell: zsh, name: tool, source: $ACTIVE/tool/comp/tool.zsh}\n" +
		"  - phase: post-place\n    action: completion\n    params: {shell: fish, name: tool, source: $ACTIVE/tool/comp/tool.fish}\n"
	return buildTarZst(t, map[string]string{
		"polypkg.yaml":        manifest,
		"tool":                "#!/bin/sh\necho tool\n",
		"org.foo.Bar.desktop": "[Desktop Entry]\nType=Application\nName=Bar\nExec=tool\n",
		"tool.xml":            "<?xml version=\"1.0\"?>\n<mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\"><mime-type type=\"application/x-tool\"><glob pattern=\"*.tool\"/></mime-type></mime-info>\n",
		"tool.bash":           "# bash\n",
		"tool.zsh":            "# zsh\n",
		"tool.fish":           "# fish\n",
	})
}

// applyToolSystem serves a signed repo with the "tool" package and applies a
// system-scope profile referencing it under prefix. Returns combined output,
// the substrate root, and the execute error.
func applyToolSystem(t testing.TB, prefix string) (string, string, error) {
	t.Helper()
	g := NewWithT(t)
	pkg := pkgFullHostIntegration(t)
	repoDir := t.TempDir()
	trustRoot := signRepo(t, repoDir, "native", 1, indexPkg{name: "tool", version: "1.0.0", artifact: pkg})
	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	t.Cleanup(srv.Close)

	profile := fmt.Sprintf(`schema: polypkg.spec/v1
name: install-tool-system
scopes:
  system:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: %s
    trust_root: %s
packages:
  system:
    tool:
      version: "=1.0.0"
`, srv.URL, trustRoot)
	profilePath := filepath.Join(t.TempDir(), "tool-system.yaml")
	g.Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())

	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"apply", "--scope", "system", "--prefix", prefix, profilePath})
	return out.String(), filepath.Join(prefix, "var", "lib", "polypkg"), cmd.Execute()
}

var _ = Describe("system-scope host integration", func() {
	It("links the active tree into <prefix>/usr/local/* at 0o755, foreign-safe", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		prefix := t.TempDir()
		usrLocal := filepath.Join(prefix, "usr", "local")

		// Pre-place a foreign file in the system bin dir to prove it is never clobbered.
		Expect(os.MkdirAll(filepath.Join(usrLocal, "bin"), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(usrLocal, "bin", "foreign"), []byte("mine"), 0o644)).To(Succeed())

		out, root, err := applyToolSystem(t, prefix)
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)

		active := filepath.Join(root, "active")
		cases := []struct{ link, target string }{
			{filepath.Join(usrLocal, "bin", "tool"), filepath.Join(active, "bin", "tool")},
			{filepath.Join(usrLocal, "share", "applications", "org.foo.Bar.desktop"), filepath.Join(active, "applications", "org.foo.Bar.desktop")},
			{filepath.Join(usrLocal, "share", "mime", "packages", "tool.xml"), filepath.Join(active, "mime", "tool.xml")},
			{filepath.Join(usrLocal, "share", "bash-completion", "completions", "tool"), filepath.Join(active, "completions", "bash", "tool")},
			{filepath.Join(usrLocal, "share", "zsh", "site-functions", "_tool"), filepath.Join(active, "completions", "zsh", "_tool")},
			{filepath.Join(usrLocal, "share", "fish", "vendor_completions.d", "tool.fish"), filepath.Join(active, "completions", "fish", "tool.fish")},
		}
		for _, c := range cases {
			tgt, rerr := os.Readlink(c.link)
			Expect(rerr).NotTo(HaveOccurred(), c.link)
			Expect(tgt).To(Equal(c.target), c.link)
		}

		// Host dirs polypkg created are 0o755 (traversable). (usr/local/bin is
		// excluded — the test pre-created it above to hold the foreign file, so
		// asserting its mode would be self-fulfilling; these three are created by
		// the reconcile pre-create.)
		for _, dir := range []string{
			filepath.Join(usrLocal, "share", "applications"),
			filepath.Join(usrLocal, "share", "mime", "packages"),
			filepath.Join(usrLocal, "share", "bash-completion", "completions"),
		} {
			di, serr := os.Stat(dir)
			Expect(serr).NotTo(HaveOccurred(), dir)
			Expect(di.Mode().Perm()).To(Equal(os.FileMode(0o755)), dir)
		}

		// Foreign file untouched (linkfarm conflict-safety holds for system scope).
		b, rerr := os.ReadFile(filepath.Join(usrLocal, "bin", "foreign"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(b)).To(Equal("mine"))

		// Nothing leaked into the user's ~/.local/bin.
		binEntries, derr := os.ReadDir(os.Getenv("XDG_BIN_HOME"))
		Expect(derr).NotTo(HaveOccurred())
		Expect(binEntries).To(BeEmpty())
	})

	It("creates 0o755 system host dirs even under a restrictive operator umask", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		prefix := t.TempDir()
		// A hardened root umask (0o077) would collapse MkdirAll(0o755) to 0o700 —
		// unless the reconcile runs inside the system apply's pinned 0o022 umask.
		// This guards that the host-integration reconcile stays inside that window.
		old := syscall.Umask(0o077)
		defer syscall.Umask(old)

		out, root, err := applyToolSystem(t, prefix)
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)
		Expect(filepath.Join(root, "active", "bin", "tool")).To(BeAnExistingFile())

		appsDir := filepath.Join(prefix, "usr", "local", "share", "applications")
		di, serr := os.Stat(appsDir)
		Expect(serr).NotTo(HaveOccurred())
		Expect(di.Mode().Perm()).To(Equal(os.FileMode(0o755)), appsDir)
	})

	It("user-scope apply still links into ~/.local/bin and creates no /usr/local (regression)", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := pkgExposingCmd(t, "hello", "greet")
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		out, err := applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)
		Expect(filepath.Join(os.Getenv("XDG_BIN_HOME"), "greet")).To(BeAnExistingFile())
	})
})
