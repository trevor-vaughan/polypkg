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

// pkgShippingMime builds a package "tool" that installs a shared-mime-info .xml
// into its own namespace and declares a mime action for it.
func pkgShippingMime(t testing.TB) []byte {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: tool\nversion: 1.0.0\nactions:\n" +
		"  - phase: pre-place\n    action: install\n    params: {src: $PKG/tool.xml, dest: $ACTIVE/tool/share/tool.xml, policy: symlink}\n" +
		"  - phase: post-place\n    action: mime\n    params: {source: $ACTIVE/tool/share/tool.xml}\n"
	return buildTarZst(t, map[string]string{
		"polypkg.yaml": manifest,
		"tool.xml": "<?xml version=\"1.0\"?>\n<mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\">\n" +
			"  <mime-type type=\"application/x-tool\"><glob pattern=\"*.tool\"/></mime-type>\n</mime-info>\n",
	})
}

var _ = Describe("mime install e2e", func() {
	dataHome := func() string { return filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg") }
	mimeHost := func() string { return filepath.Join(os.Getenv("XDG_DATA_HOME"), "mime", "packages") }
	activeMime := func() string { return filepath.Join(dataHome(), "active", "mime") }

	It("installs the .xml on apply, is foreign-safe, and prunes on unlink", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := pkgShippingMime(t)
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1, indexPkg{name: "tool", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		// Pre-create a foreign .xml to prove it is never clobbered.
		Expect(os.MkdirAll(mimeHost(), 0o750)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(mimeHost(), "foreign.xml"), []byte("mine"), 0o644)).To(Succeed())

		out, err := applyProfileWith(t, srv.URL, trust, "tool")
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)

		link := filepath.Join(mimeHost(), "tool.xml")
		tgt, err := os.Readlink(link)
		Expect(err).NotTo(HaveOccurred())
		Expect(tgt).To(Equal(filepath.Join(activeMime(), "tool.xml")))

		b, readErr := os.ReadFile(filepath.Join(mimeHost(), "foreign.xml"))
		Expect(readErr).NotTo(HaveOccurred())
		Expect(string(b)).To(Equal("mine"))

		_, err = runUnlinkInProcess()
		Expect(err).NotTo(HaveOccurred())
		_, statErr := os.Lstat(link)
		Expect(os.IsNotExist(statErr)).To(BeTrue())
		_, err = os.Lstat(filepath.Join(mimeHost(), "foreign.xml"))
		Expect(err).NotTo(HaveOccurred())
	})

	It("does not write into the mime packages dir when mime.enabled=false", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		t.Setenv("POLYPKG_MIME_ENABLED", "false")
		pkg := pkgShippingMime(t)
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1, indexPkg{name: "tool", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		out, err := applyProfileWith(t, srv.URL, trust, "tool")
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)
		_, statErr := os.Lstat(filepath.Join(mimeHost(), "tool.xml"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
	})
})
