package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/cli"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
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

	// Mirrors the freshness suite's build+clock pattern (signed local repo over
	// HTTP, trust clock advanced past the metadata expiry) but grants the source
	// accept_expiry_until grace so the fetch is accepted rather than refused. The
	// durable per-source grace marker persisted by that apply must then surface in
	// the status JSON.
	Context("with a source last fetched under freshness grace (2e-1)", func() {
		It("--format json surfaces the freshness_grace entry for the graced source", func() {
			t := GinkgoTB()
			IsolatedEnv(t)
			pkg := buildHelloPackage(t)
			repoDir := t.TempDir()
			// signRepo stamps Expires=2099 into the trust document and index;
			// advancing the trust clock past that (below) makes the metadata
			// expired-but-graced rather than fresh.
			trustRoot := signRepo(t, repoDir, "native", 1,
				indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
			srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
			DeferCleanup(srv.Close)

			// Grant the native source accept_expiry_until out to 2999 — well past
			// the 2099 metadata expiry the jumped clock crosses — so the expired
			// metadata is accepted under grace instead of refused.
			profile := installHelloProfile(t, srv.URL, trustRoot)
			profile = strings.Replace(profile,
				"trust_root: "+trustRoot,
				"trust_root: "+trustRoot+"\n    accept_expiry_until: \"2999-01-01T00:00:00Z\"", 1)
			profilePath := filepath.Join(t.TempDir(), "profile.yaml")
			Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())

			// Advance the freshness clock past the 2099 metadata expiry so the fetch
			// is admitted only under grace, persisting the durable per-source marker.
			restore := trust.SetTimeNowForTesting(func() time.Time {
				return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
			})
			DeferCleanup(restore)

			out, err := runCmd("apply", profilePath)
			Expect(err).NotTo(HaveOccurred(), "graced apply: %s", out)

			jsonOut, serr := runStatusCmd("--format", "json")
			Expect(serr).NotTo(HaveOccurred())
			sr, perr := schema.ParseStatusResult(strings.NewReader(lastNonEmptyLine(jsonOut)))
			Expect(perr).NotTo(HaveOccurred())
			Expect(sr.FreshnessGrace).To(HaveLen(1))
			Expect(sr.FreshnessGrace[0].Source).To(Equal("native"))
			Expect(sr.FreshnessGrace[0].AcceptUntil).To(Equal("2999-01-01T00:00:00Z"))
			Expect(sr.FreshnessGrace[0].Docs).To(ContainElement("index"))
			// The accept_expiry_until deadline (2999) is still in the future at real
			// status time, so the window is not itself expired.
			Expect(sr.FreshnessGrace[0].WindowExpired).To(BeFalse())
		})
	})

	// The apply->publish-revocation->status e2e is out of scope here: the
	// builder-verified carriage and revocation-list publishing helpers live in
	// internal/planner's private tests, not in this suite. Instead we place the
	// generation manifest (with a builder-verified binding) and the per-source
	// trust-state Seen file (listing the binding's key as revoked) directly on
	// disk, then drive the REAL status command to guard the cobra wiring, the
	// revoked_builders JSON field, and the exit-code-3 contract end to end.
	Context("with an installed package whose builder key is revoked", func() {
		It("--format json surfaces revoked_builders and exits 3", func() {
			t := GinkgoTB()
			root := IsolatedEnv(t)
			storeRoot := filepath.Join(root, "data", "polypkg")
			trustDir := filepath.Join(root, "state", "polypkg", "trust")

			gen1 := filepath.Join(storeRoot, "generations", "1")
			Expect(os.MkdirAll(filepath.Join(gen1, "active"), 0o700)).To(Succeed())
			Expect(os.Symlink(filepath.Join("generations", "1", "active"),
				filepath.Join(storeRoot, "active"))).To(Succeed())
			Expect(os.WriteFile(filepath.Join(gen1, "ownership.json"),
				[]byte(`{"schema":"polypkg.ownership/v1","scope":"user","entries":[]}`), 0o600)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(gen1, "manifest.json"), []byte(`{
  "schema":"polypkg.manifest/v2","generation":1,"scope":"user",
  "produced_by":{"tool":"polypkg","version":"0.1.0","timestamp":"2026-01-01T00:00:00Z","host":"test"},
  "entries":[
    {"name":"hello","version":"1.0.0","content_hash":"blake3:aabbcc",
     "attestation":{"status":"verified","policy_at_install":"warn",
       "carried_bindings":[{"predicate_type":"p","format":"f","subject_scope":"artifact","tier":"builder-verified","verifying_key_id":"builder-a"}]}}
  ]}`), 0o600)).To(Succeed())

			Expect(os.MkdirAll(trustDir, 0o700)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(trustDir, "repo.json"),
				[]byte(`{"trust_serial":1,"index_serial":1,"revoked_builder_keys":["builder-a"]}`), 0o600)).To(Succeed())

			out, err := runStatusCmd("--format", "json")
			sr, perr := schema.ParseStatusResult(strings.NewReader(lastNonEmptyLine(out)))
			Expect(perr).NotTo(HaveOccurred())
			Expect(sr.RevokedBuilders).To(HaveLen(1))
			Expect(sr.RevokedBuilders[0].Package).To(Equal("hello"))
			Expect(sr.RevokedBuilders[0].KeyID).To(Equal("builder-a"))
			// The runner returns the command error, so the exit-code contract
			// (cli.ExitCode == 3 -> process exit 3) is asserted here too.
			Expect(cli.ExitCode(err)).To(Equal(3))
		})
	})
})
