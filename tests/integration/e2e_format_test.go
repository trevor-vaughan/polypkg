package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/cli"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func executeWithFormatJSON(args ...string) (string, error) {
	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"--format", "json"}, args...))
	err := cmd.Execute()
	return out.String(), err
}

// parseLastCLIResult parses the last JSON line of stdout/stderr output.
// Some commands log warnings via slog (text) before emitting the
// envelope, so we take the trailing JSON line.
func parseLastCLIResult(output string) *schema.CLIResult {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	last := lines[len(lines)-1]
	r, err := schema.ParseCLIResult(strings.NewReader(last))
	Expect(err).NotTo(HaveOccurred())
	return r
}

var _ = Describe("--format json on action commands", func() {
	var (
		repoDir   string
		srv       *httptest.Server
		trustRoot string
		profile   string
	)

	BeforeEach(func() {
		IsolatedEnv(GinkgoTB())
		pkg := buildHelloPackage(GinkgoTB())
		repoDir = GinkgoT().TempDir()
		trustRoot = signRepo(GinkgoTB(), repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv = httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)
		profile = filepath.Join(GinkgoT().TempDir(), "profile.yaml")
		Expect(os.WriteFile(profile, []byte(installHelloProfile(GinkgoTB(), srv.URL, trustRoot)), 0o644)).To(Succeed())
	})

	It("apply emits an ok envelope with gen_id", func() {
		out, err := executeWithFormatJSON("apply", profile)
		Expect(err).NotTo(HaveOccurred())
		r := parseLastCLIResult(out)
		Expect(r.Command).To(Equal("apply"))
		Expect(r.Status).To(Equal("ok"))
		Expect(r.Data["gen_id"]).To(BeEquivalentTo(1))
	})

	It("apply emits an error envelope on profile parse failure", func() {
		badProfile := filepath.Join(GinkgoT().TempDir(), "bad.yaml")
		Expect(os.WriteFile(badProfile, []byte("invalid: yaml: : :"), 0o644)).To(Succeed())
		out, err := executeWithFormatJSON("apply", badProfile)
		Expect(err).To(HaveOccurred())
		r := parseLastCLIResult(out)
		Expect(r.Status).To(Equal("error"))
		Expect(r.Error).NotTo(BeEmpty())
	})

	It("rollback emits an envelope (apply twice, then rollback to gen 1)", func() {
		_, applyErr := executeWithFormatJSON("apply", profile)
		Expect(applyErr).NotTo(HaveOccurred())
		_, applyErr = executeWithFormatJSON("apply", profile, "--no-drift-check")
		Expect(applyErr).NotTo(HaveOccurred())
		out, err := executeWithFormatJSON("rollback", "--to", "1")
		Expect(err).NotTo(HaveOccurred())
		r := parseLastCLIResult(out)
		Expect(r.Command).To(Equal("rollback"))
		Expect(r.Status).To(Equal("ok"))
		Expect(r.Data["target"]).To(BeEquivalentTo(1))
	})

	It("gc emits an envelope", func() {
		_, err := executeWithFormatJSON("apply", profile)
		Expect(err).NotTo(HaveOccurred())
		out, err := executeWithFormatJSON("gc", "--count", "1", "--age", "0s")
		Expect(err).NotTo(HaveOccurred())
		r := parseLastCLIResult(out)
		Expect(r.Command).To(Equal("gc"))
		Expect(r.Status).To(Equal("ok"))
	})

	It("generation pin emits an envelope", func() {
		_, err := executeWithFormatJSON("apply", profile)
		Expect(err).NotTo(HaveOccurred())
		out, err := executeWithFormatJSON("generation", "pin", "1", "--reason", "test")
		Expect(err).NotTo(HaveOccurred())
		r := parseLastCLIResult(out)
		Expect(r.Command).To(Equal("pin"))
		Expect(r.Status).To(Equal("ok"))
		Expect(r.Data["gen_id"]).To(BeEquivalentTo(1))
	})

	It("generation unpin emits an envelope", func() {
		_, err := executeWithFormatJSON("apply", profile)
		Expect(err).NotTo(HaveOccurred())
		_, err = executeWithFormatJSON("generation", "pin", "1")
		Expect(err).NotTo(HaveOccurred())
		out, err := executeWithFormatJSON("generation", "unpin", "1")
		Expect(err).NotTo(HaveOccurred())
		r := parseLastCLIResult(out)
		Expect(r.Command).To(Equal("unpin"))
		Expect(r.Status).To(Equal("ok"))
	})
})
