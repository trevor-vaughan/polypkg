package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/cli"
)

// installHelloSystemProfile renders the system-scope fixture with a concrete
// repo URL and trust-root path.
func installHelloSystemProfile(t testing.TB, repoURL, trustRoot string) string {
	t.Helper()
	g := NewWithT(t)
	tmpl, err := os.ReadFile(filepath.Join("..", "fixtures", "profiles", "install-hello-system.yaml"))
	g.Expect(err).NotTo(HaveOccurred())
	p := strings.ReplaceAll(string(tmpl), "FIXTURE_REPO_URL", repoURL)
	return strings.ReplaceAll(p, "FIXTURE_TRUST_ROOT", trustRoot)
}

// applySystemHello serves a signed one-package repo and runs apply/plan in
// process for the system-scope fixture. It returns combined output, the
// substrate root under the prefix, and the execute error.
func applySystemHello(t testing.TB, prefix string, args ...string) (string, string, error) {
	t.Helper()
	g := NewWithT(t)
	pkg := pkgExposingCmd(t, "hello", "greet")
	repoDir := t.TempDir()
	trustRoot := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	t.Cleanup(srv.Close)

	profilePath := filepath.Join(t.TempDir(), "system.yaml")
	g.Expect(os.WriteFile(profilePath, []byte(installHelloSystemProfile(t, srv.URL, trustRoot)), 0o644)).To(Succeed())

	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	full := append(append([]string{}, args...), "--prefix", prefix, profilePath)
	cmd.SetArgs(full)
	err := cmd.Execute()
	return out.String(), filepath.Join(prefix, "var", "lib", "polypkg"), err
}

var _ = Describe("system-scope apply (prefix/DESTDIR model)", func() {
	It("builds a 0o755 system generation under the prefix and skips host integration", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		prefix := t.TempDir()

		out, root, err := applySystemHello(t, prefix, "apply", "--scope", "system")
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)
		Expect(out).To(ContainSubstring("applied generation 1"))

		// Generation + active tree built under the prefix.
		target, rerr := os.Readlink(filepath.Join(root, "active"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(target).To(Equal(filepath.Join("generations", "1", "active")))
		// The path action placed the shared command symlink in the active tree.
		Expect(filepath.Join(root, "active", "bin", "greet")).To(BeAnExistingFile())
		// State-home wiring: the runner's audit log lands under the prefix root
		// (for system scope stateHome == dataHome == the substrate root).
		Expect(filepath.Join(root, "audit.log")).To(BeAnExistingFile())

		// System dir modes: root (pre-create seam), generation, and active-tree
		// dirs are 0o755 so other users can traverse to installed commands.
		for _, dir := range []string{
			root,
			filepath.Join(root, "generations", "1"),
			filepath.Join(root, "generations", "1", "active"),
			filepath.Join(root, "active", "bin"),
			filepath.Join(root, "active", "hello", "bin"),
		} {
			di, serr := os.Stat(dir)
			Expect(serr).NotTo(HaveOccurred(), dir)
			Expect(di.Mode().Perm()).To(Equal(os.FileMode(0o755)), dir)
		}

		// Host integration is skipped for system scope (SP2): the bridge did NOT
		// link greet into the user's ~/.local/bin (XDG_BIN_HOME under IsolatedEnv).
		binEntries, derr := os.ReadDir(os.Getenv("XDG_BIN_HOME"))
		Expect(derr).NotTo(HaveOccurred())
		Expect(binEntries).To(BeEmpty(), "system apply must not create user ~/.local/bin links")
	})

	It("enforces 0o755 system dir modes even under a restrictive operator umask", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		prefix := t.TempDir()
		// Simulate a hardened root umask (0o077). Without the apply pinning its own
		// 0o022 umask, every MkdirAll(0o755) would collapse to 0o700 and the
		// multi-user traversal chain would silently break. Restored after the spec.
		old := syscall.Umask(0o077)
		defer syscall.Umask(old)

		out, root, err := applySystemHello(t, prefix, "apply", "--scope", "system")
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)
		for _, dir := range []string{
			root,
			filepath.Join(root, "generations", "1", "active"),
			filepath.Join(root, "active", "bin"),
			filepath.Join(root, "active", "hello", "bin"),
		} {
			di, serr := os.Stat(dir)
			Expect(serr).NotTo(HaveOccurred(), dir)
			Expect(di.Mode().Perm()).To(Equal(os.FileMode(0o755)), dir)
		}
	})

	It("leaves user-scope apply linking into ~/.local/bin (regression)", func() {
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

	It("plan --scope system previews the system package set under the prefix", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		prefix := t.TempDir()

		out, root, err := applySystemHello(t, prefix, "plan", "--scope", "system")
		// plan exits non-zero ("changes pending") when there is an install to do.
		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring("hello"))
		// plan is read-only on the data side: it builds no generation.
		_, statErr := os.Stat(filepath.Join(root, "generations"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
	})

	It("list and info honor POLYPKG_SYSTEM_PREFIX env after a prefixed apply", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		prefix := t.TempDir()

		// Apply using --prefix flag (the writer path).
		out, _, err := applySystemHello(t, prefix, "apply", "--scope", "system")
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)
		Expect(out).To(ContainSubstring("applied generation 1"))

		// Set POLYPKG_SYSTEM_PREFIX so list/info pick up the prefix without --prefix.
		t.Setenv("POLYPKG_SYSTEM_PREFIX", prefix)

		// list --scope system must find hello 1.0.0 (not report empty).
		listOut, listErr := runCmd("list", "--scope", "system")
		Expect(listErr).NotTo(HaveOccurred(), "list output: %s", listOut)
		Expect(listOut).To(ContainSubstring("hello"),
			"list must find hello installed under the prefixed system stateHome; output:\n%s", listOut)
		Expect(listOut).To(ContainSubstring("1.0.0"),
			"list must report the installed version; output:\n%s", listOut)

		// info hello --scope system must show installed: 1.0.0.
		// info fetches the catalog, which requires the profile; set it via env.
		profileContent := installHelloSystemProfile(t, "http://127.0.0.1:1", "/dev/null")
		profilePath := filepath.Join(t.TempDir(), "system.yaml")
		Expect(os.WriteFile(profilePath, []byte(profileContent), 0o644)).To(Succeed())
		t.Setenv("POLYPKG_PROFILE", profilePath)

		infoOut, infoErr := runCmd("info", "--scope", "system", "hello")
		// info may fail to fetch catalog (unreachable source) but must show installed
		// version from the prefixed stateHome (offline-tolerance path).
		if infoErr != nil {
			// The offline-tolerance path only triggers when the package is installed.
			// If we reached the error path here, info did NOT find the installed
			// package — that is the bug we are guarding against.
			Expect(infoOut).To(ContainSubstring("installed: 1.0.0"),
				"info must report installed version even when catalog is unreachable; output:\n%s", infoOut)
		} else {
			Expect(infoOut).To(ContainSubstring("installed: 1.0.0"),
				"info must report installed version; output:\n%s", infoOut)
		}
	})

	It("list honors profile.scopes.system.prefix after a prefixed apply", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		prefix := t.TempDir()

		// Apply using --prefix flag.
		out, _, err := applySystemHello(t, prefix, "apply", "--scope", "system")
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)
		Expect(out).To(ContainSubstring("applied generation 1"))

		// Build a profile with scopes.system.prefix set; no --prefix flag, no env.
		t.Setenv("POLYPKG_SYSTEM_PREFIX", "")
		profileContent := installHelloSystemProfile(t, "http://127.0.0.1:1", "/dev/null")
		// Inject the prefix into the profile's system scope.
		profileContent += "  # injected by test\n"
		profileContent = strings.ReplaceAll(profileContent,
			"  system:\n    substrate: store\n",
			"  system:\n    substrate: store\n    prefix: "+prefix+"\n")
		profilePath := filepath.Join(t.TempDir(), "system.yaml")
		Expect(os.WriteFile(profilePath, []byte(profileContent), 0o644)).To(Succeed())
		t.Setenv("POLYPKG_PROFILE", profilePath)

		listOut, listErr := runCmd("list", "--scope", "system")
		Expect(listErr).NotTo(HaveOccurred(), "list output: %s", listOut)
		Expect(listOut).To(ContainSubstring("hello"),
			"list must find hello when prefix comes from profile.scopes.system.prefix; output:\n%s", listOut)
	})
})
