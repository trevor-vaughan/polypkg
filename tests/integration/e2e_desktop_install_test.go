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

// pkgShippingDesktop builds a package "tool" that installs a .desktop file into
// its own namespace and declares a desktop action for it.
func pkgShippingDesktop(t testing.TB) []byte {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: tool\nversion: 1.0.0\nactions:\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/org.foo.Bar.desktop, dest: $ACTIVE/tool/share/org.foo.Bar.desktop, policy: symlink}\n" +
		"  - phase: post-place\n    action: desktop\n    params: {source: $ACTIVE/tool/share/org.foo.Bar.desktop}\n"
	return buildTarZst(t, map[string]string{
		"polypkg.yaml":        manifest,
		"org.foo.Bar.desktop": "[Desktop Entry]\nType=Application\nName=Bar\nExec=tool\n",
	})
}

var _ = Describe("desktop install e2e", func() {
	dataHome := func() string { return filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg") }
	appsHost := func() string { return filepath.Join(os.Getenv("XDG_DATA_HOME"), "applications") }
	activeApps := func() string { return filepath.Join(dataHome(), "active", "applications") }

	It("installs the .desktop entry on apply, is foreign-safe, and prunes on unlink", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := pkgShippingDesktop(t)
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1, indexPkg{name: "tool", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		// Pre-create a foreign .desktop to prove it is never clobbered.
		Expect(os.MkdirAll(appsHost(), 0o750)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(appsHost(), "foreign.desktop"), []byte("mine"), 0o644)).To(Succeed())

		out, err := applyProfileWith(t, srv.URL, trust, "tool")
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)

		link := filepath.Join(appsHost(), "org.foo.Bar.desktop")
		tgt, err := os.Readlink(link)
		Expect(err).NotTo(HaveOccurred())
		Expect(tgt).To(Equal(filepath.Join(activeApps(), "org.foo.Bar.desktop")))

		b, readErr := os.ReadFile(filepath.Join(appsHost(), "foreign.desktop"))
		Expect(readErr).NotTo(HaveOccurred())
		Expect(string(b)).To(Equal("mine"))

		_, err = runUnlinkInProcess()
		Expect(err).NotTo(HaveOccurred())
		_, statErr := os.Lstat(link)
		Expect(os.IsNotExist(statErr)).To(BeTrue())
		_, err = os.Lstat(filepath.Join(appsHost(), "foreign.desktop"))
		Expect(err).NotTo(HaveOccurred())
	})

	It("does not write into the applications dir when desktop.enabled=false", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		t.Setenv("POLYPKG_DESKTOP_ENABLED", "false")
		pkg := pkgShippingDesktop(t)
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1, indexPkg{name: "tool", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		out, err := applyProfileWith(t, srv.URL, trust, "tool")
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)
		_, statErr := os.Lstat(filepath.Join(appsHost(), "org.foo.Bar.desktop"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
	})
})
