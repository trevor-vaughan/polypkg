package integration

import (
	"archive/tar"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/cli"
)

// maliciousPackage builds a signed-quality tar.zst whose manifest is valid but
// which also carries a hostile entry, so the whole apply pipeline (fetch ->
// verify -> extract -> dispatch) can be exercised against an attack.
func maliciousPackage(t testing.TB, evil tar.Header, evilBody []byte) []byte {
	t.Helper()
	g := NewWithT(t)
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	manifest := "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"
	g.Expect(tw.WriteHeader(&tar.Header{
		Name: "polypkg.yaml", Size: int64(len(manifest)), Mode: 0o644, Typeflag: tar.TypeReg,
	})).To(Succeed())
	_, err := tw.Write([]byte(manifest))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(tw.WriteHeader(&evil)).To(Succeed())
	if len(evilBody) > 0 {
		_, err = tw.Write(evilBody)
		g.Expect(err).NotTo(HaveOccurred())
	}
	g.Expect(tw.Close()).To(Succeed())

	var z bytes.Buffer
	zw, err := zstd.NewWriter(&z)
	g.Expect(err).NotTo(HaveOccurred())
	_, err = zw.Write(raw.Bytes())
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(zw.Close()).To(Succeed())
	return z.Bytes()
}

// applyMaliciousAndAssertRejected serves the package (correctly signed so it
// passes verification), applies it, and asserts the apply fails with no
// generation activated. The package must be hostile only via extraction.
func applyMaliciousAndAssertRejected(t testing.TB, pkg []byte) {
	t.Helper()
	g := NewWithT(t)
	IsolatedEnv(t)

	repoDir := t.TempDir()
	trustRoot := signRepo(t, repoDir, "native", 1,
		indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	profilePath := filepath.Join(t.TempDir(), "profile.yaml")
	g.Expect(os.WriteFile(profilePath, []byte(installHelloProfile(t, srv.URL, trustRoot)), 0o644)).To(Succeed())

	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"apply", profilePath})
	g.Expect(cmd.Execute()).To(HaveOccurred(), "apply must reject the hostile package")

	dataHome := os.Getenv("XDG_DATA_HOME")
	_, statErr := os.Lstat(filepath.Join(dataHome, "polypkg", "active"))
	g.Expect(statErr).To(HaveOccurred(), "no generation may be activated for a rejected package")
}

var _ = Describe("adversarial packages", func() {
	It("rejects a package with a path-traversal entry", func() {
		t := GinkgoTB()
		pkg := maliciousPackage(t,
			tar.Header{Name: "../../../../etc/cron.d/pwned", Mode: 0o644, Typeflag: tar.TypeReg, Size: 5},
			[]byte("pwned"),
		)
		applyMaliciousAndAssertRejected(t, pkg)
	})

	It("rejects a package with an escaping symlink", func() {
		t := GinkgoTB()
		pkg := maliciousPackage(t,
			tar.Header{Name: "lib", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "../../../../../../etc"},
			nil,
		)
		applyMaliciousAndAssertRejected(t, pkg)
	})
})
