package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// runPkgJSON runs `polypkg --format json <args>` in-process and returns its
// stdout and stderr separately, so a test can require that stdout holds
// nothing but JSON.
func runPkgJSON(args ...string) (stdout, stderr string, err error) {
	root := NewRootCmd()
	root.SilenceUsage, root.SilenceErrors = true, true
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"--format", "json"}, args...))
	err = root.Execute()
	return out.String(), errOut.String(), err
}

// expectErrorEnvelope requires stdout to be exactly one cli-result/v2 error
// envelope naming command, and returns its error sentence.
func expectErrorEnvelope(stdout, command string) string {
	GinkgoHelper()
	var env struct {
		Schema  string `json:"schema"`
		Command string `json:"command"`
		Status  string `json:"status"`
		Error   string `json:"error"`
	}
	Expect(json.Unmarshal([]byte(stdout), &env)).To(Succeed(), "stdout must be one JSON envelope, got %q", stdout)
	Expect(env.Schema).To(Equal("polypkg.cli-result/v2"))
	Expect(env.Command).To(Equal(command))
	Expect(env.Status).To(Equal("error"))
	Expect(env.Error).NotTo(BeEmpty())
	return env.Error
}

var _ = Describe("pkg commands under --format json", func() {
	BeforeEach(func() { sandboxUserEnv(GinkgoTB()) })

	It("pkg init prints an error envelope for an invalid package name", func() {
		stdout, _, err := runPkgJSON("pkg", "init", "--name", "not a slug", GinkgoT().TempDir())
		Expect(err).To(HaveOccurred())
		Expect(expectErrorEnvelope(stdout, "pkg init")).To(ContainSubstring("not a valid slug"))
	})

	It("pkg init prints an error envelope when polypkg.yaml already exists", func() {
		dir := GinkgoT().TempDir()
		writeCleanPkg(dir)
		stdout, _, err := runPkgJSON("pkg", "init", dir)
		Expect(err).To(HaveOccurred())
		Expect(expectErrorEnvelope(stdout, "pkg init")).To(ContainSubstring("already exists"))
	})

	It("pkg lint prints an error envelope for -o without --sarif", func() {
		stdout, _, err := runPkgJSON("pkg", "lint", "-o", "x.sarif", GinkgoT().TempDir())
		Expect(err).To(HaveOccurred())
		Expect(expectErrorEnvelope(stdout, "pkg lint")).To(ContainSubstring("--sarif"))
	})

	It("pkg lint sends its findings to stderr and only the envelope to stdout", func() {
		dir := GinkgoT().TempDir()
		writeUnknownActionPkg(dir)
		stdout, stderr, err := runPkgJSON("pkg", "lint", dir)
		Expect(err).To(HaveOccurred())
		Expect(expectErrorEnvelope(stdout, "pkg lint")).To(ContainSubstring("error-severity"))
		Expect(stderr).To(ContainSubstring("PKG000"))
	})

	It("pkg lint --sarif keeps stdout a single SARIF document when findings fail the lint", func() {
		dir := GinkgoT().TempDir()
		writeUnknownActionPkg(dir)
		stdout, _, err := runPkgJSON("pkg", "lint", "--sarif", dir)
		Expect(err).To(HaveOccurred())
		var doc struct {
			Version string `json:"version"`
		}
		Expect(json.Unmarshal([]byte(stdout), &doc)).To(Succeed(), "stdout must be one SARIF document, got %q", stdout)
		Expect(doc.Version).To(Equal("2.1.0"))
	})

	It("pkg lint --sarif -o prints the error envelope, since stdout is otherwise empty", func() {
		dir := GinkgoT().TempDir()
		writeUnknownActionPkg(dir)
		stdout, _, err := runPkgJSON("pkg", "lint", "--sarif", "-o", filepath.Join(GinkgoT().TempDir(), "r.sarif"), dir)
		Expect(err).To(HaveOccurred())
		expectErrorEnvelope(stdout, "pkg lint")
	})

	It("pkg build prints an error envelope when the output directory cannot be created", func() {
		blocker := filepath.Join(GinkgoT().TempDir(), "file")
		Expect(os.WriteFile(blocker, nil, 0o644)).To(Succeed())
		dir := GinkgoT().TempDir()
		writeCleanPkg(dir)
		stdout, _, err := runPkgJSON("pkg", "build", "-o", filepath.Join(blocker, "out"), dir)
		Expect(err).To(HaveOccurred())
		Expect(expectErrorEnvelope(stdout, "pkg build")).To(ContainSubstring("output dir"))
	})

	It("pkg build sends lint findings to stderr and only the envelope to stdout", func() {
		dir := GinkgoT().TempDir()
		writeUnknownActionPkg(dir)
		stdout, stderr, err := runPkgJSON("pkg", "build", "-o", GinkgoT().TempDir(), dir)
		Expect(err).To(HaveOccurred())
		Expect(expectErrorEnvelope(stdout, "pkg build")).To(Equal("lint found error-severity issues; not packing"))
		Expect(stderr).To(ContainSubstring("PKG000"))
	})
})
