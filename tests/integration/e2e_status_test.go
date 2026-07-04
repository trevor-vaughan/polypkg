package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/cli"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func runStatusCmd(args ...string) (string, error) {
	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(append([]string{"status"}, args...))
	err := cmd.Execute()
	return buf.String(), err
}

// lastNonEmptyLine extracts the final non-empty line, used to skip past any
// warnings (e.g. drift inspect failure) that may precede the JSON envelope.
func lastNonEmptyLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[i]
		}
	}
	return ""
}

var _ = Describe("status", func() {
	Context("with no generation applied", func() {
		BeforeEach(func() { IsolatedEnv(GinkgoTB()) })

		It("prints 'no generation applied yet' (text)", func() {
			out, err := runStatusCmd()
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("no generation applied yet"))
		})

		It("emits an empty retained list (json)", func() {
			out, err := runStatusCmd("--format", "json")
			Expect(err).NotTo(HaveOccurred())
			sr, perr := schema.ParseStatusResult(strings.NewReader(lastNonEmptyLine(out)))
			Expect(perr).NotTo(HaveOccurred())
			Expect(sr.Schema).To(Equal("polypkg.status/v1"))
			Expect(sr.Retained).To(BeEmpty())
			Expect(sr.Current).To(BeNil())
		})
	})

	Context("with a current generation", func() {
		var (
			repoDir   string
			srv       *httptest.Server
			trustRoot string
		)

		BeforeEach(func() {
			IsolatedEnv(GinkgoTB())
			pkg := buildHelloPackage(GinkgoTB())
			repoDir = GinkgoT().TempDir()
			trustRoot = signRepo(GinkgoTB(), repoDir, "native", 1,
				indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
			srv = httptest.NewServer(http.FileServer(http.Dir(repoDir)))
			DeferCleanup(srv.Close)
			_, applyErr := applyHelloOnce(GinkgoTB(), srv.URL, trustRoot)
			Expect(applyErr).NotTo(HaveOccurred())
		})

		It("default verbosity prints a one-line summary", func() {
			out, err := runStatusCmd()
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(MatchRegexp(`current generation: 1\s+retained: 1`))
		})

		It("-v adds the per-generation list", func() {
			out, err := runStatusCmd("-v")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("retained generations:"))
			Expect(out).To(MatchRegexp(`\* 1`))
		})

		It("-vv keeps the retained list (drift block omitted when clean)", func() {
			// No live mutation -> Inspect returns zero drifted entries, so the
			// drift detail block is intentionally omitted; the retained list
			// from -v still appears.
			out, err := runStatusCmd("-vv")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("retained generations:"))
		})

		It("-vvv adds GC preview", func() {
			out, err := runStatusCmd("-vvv")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("GC preview"))
			Expect(out).To(ContainSubstring("would keep"))
		})

		It("--format json emits polypkg.status/v1 with verbosity flags ignored", func() {
			out, err := runStatusCmd("--format", "json", "-vvv")
			Expect(err).NotTo(HaveOccurred())
			sr, perr := schema.ParseStatusResult(strings.NewReader(lastNonEmptyLine(out)))
			Expect(perr).NotTo(HaveOccurred())
			Expect(sr.Schema).To(Equal("polypkg.status/v1"))
			Expect(sr.Current).NotTo(BeNil())
			Expect(sr.Current.Generation).To(Equal(1))
			Expect(sr.Retained).To(HaveLen(1))
			Expect(sr.Retained[0].ID).To(Equal(1))
			Expect(sr.Retained[0].IsCurrent).To(BeTrue())
			Expect(sr.GCPreview).NotTo(BeNil())
			Expect(sr.GCPreview.WouldKeep).To(ContainElement(1))
		})
	})
})
