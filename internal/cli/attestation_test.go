package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

func writeReportGen(storeRoot string, gen int, manifestJSON string) {
	genDir := filepath.Join(storeRoot, "generations", strconv.Itoa(gen))
	Expect(os.MkdirAll(filepath.Join(genDir, "active"), 0o700)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(genDir, "ownership.json"),
		[]byte(`{"schema":"polypkg.ownership/v1","scope":"user","entries":[]}`), 0o600)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(genDir, "manifest.json"), []byte(manifestJSON), 0o600)).To(Succeed())
}

var _ = Describe("buildAttestationReport", func() {
	It("aggregates every entry across all retained generations, deterministically", func() {
		storeRoot := GinkgoT().TempDir()
		writeReportGen(storeRoot, 1, `{
  "schema":"polypkg.manifest/v2","generation":1,"scope":"user",
  "produced_by":{"tool":"polypkg","version":"0.1.0","timestamp":"2026-01-01T00:00:00Z","host":"test"},
  "entries":[
    {"name":"bravo","version":"1.0.0","content_hash":"blake3:b",
     "attestation":{"status":"verified","policy_at_install":"warn",
       "carried_bindings":[{"predicate_type":"p","format":"f","subject_scope":"artifact","tier":"verified-offline","certificate_identity":"id@x","certificate_issuer":"https://x"}]}},
    {"name":"alpha","version":"2.0.0","content_hash":"blake3:a",
     "attestation":{"status":"unattested","policy_at_install":"warn"}}
  ]}`)
		writeReportGen(storeRoot, 2, `{
  "schema":"polypkg.manifest/v2","generation":2,"scope":"user",
  "produced_by":{"tool":"polypkg","version":"0.1.0","timestamp":"2026-01-02T00:00:00Z","host":"test"},
  "entries":[
    {"name":"alpha","version":"2.1.0","content_hash":"blake3:a2",
     "attestation":{"status":"verified","policy_at_install":"require","predicate_types":["https://slsa.dev/provenance/v1"]}},
    {"name":"charlie","version":"3.0.0","content_hash":"blake3:c"}
  ]}`)
		Expect(os.Symlink(filepath.Join("generations", "2", "active"), filepath.Join(storeRoot, "active"))).To(Succeed())

		sub, err := substrate.New("store", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		rep, err := buildAttestationReport(sub, "user", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(rep.Schema).To(Equal(schema.AttestationReportSchemaV1))
		Expect(rep.GeneratedFrom.Scope).To(Equal("user"))
		Expect(rep.GeneratedFrom.Generations).To(Equal([]int{1, 2}))

		keys := make([]string, len(rep.Packages))
		for i, p := range rep.Packages {
			keys[i] = p.Name + "@" + p.Version + "#" + strconv.Itoa(p.Generation)
		}
		Expect(keys).To(Equal([]string{"alpha@2.0.0#1", "alpha@2.1.0#2", "bravo@1.0.0#1", "charlie@3.0.0#2"}))

		get := func(name string) schema.PackageEvidence {
			for _, p := range rep.Packages {
				if p.Name == name {
					return p
				}
			}
			return schema.PackageEvidence{}
		}
		Expect(get("charlie").Status).To(BeEmpty())
		Expect(get("charlie").CarriedBindings).To(BeEmpty())
		Expect(get("charlie").ContentHash).To(Equal("blake3:c"))
		Expect(get("bravo").CarriedBindings[0].CertificateIdentity).To(Equal("id@x"))
		Expect(get("bravo").InstalledAt.Format("2006-01-02")).To(Equal("2026-01-01"))

		b1, err := json.Marshal(rep)
		Expect(err).NotTo(HaveOccurred())
		rep2, err := buildAttestationReport(sub, "user", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		b2, err := json.Marshal(rep2)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(b2)).To(Equal(string(b1)))
		Expect(string(b1)).To(ContainSubstring(`"installed_at":"2026-01-01T00:00:00Z"`))
	})

	It("orders same-name@version entries by content_hash (total order for tampered manifests)", func() {
		storeRoot := GinkgoT().TempDir()
		writeReportGen(storeRoot, 1, `{
  "schema":"polypkg.manifest/v2","generation":1,"scope":"user",
  "produced_by":{"tool":"polypkg","version":"0.1.0","timestamp":"2026-01-01T00:00:00Z","host":"test"},
  "entries":[
    {"name":"dup","version":"1.0.0","content_hash":"blake3:zzz"},
    {"name":"dup","version":"1.0.0","content_hash":"blake3:aaa"}
  ]}`)
		Expect(os.Symlink(filepath.Join("generations", "1", "active"), filepath.Join(storeRoot, "active"))).To(Succeed())
		sub, err := substrate.New("store", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		rep, err := buildAttestationReport(sub, "user", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(rep.Packages).To(HaveLen(2))
		Expect(rep.Packages[0].ContentHash).To(Equal("blake3:aaa"))
		Expect(rep.Packages[1].ContentHash).To(Equal("blake3:zzz"))
	})

	It("returns an empty report for a store with no generations", func() {
		storeRoot := GinkgoT().TempDir()
		Expect(os.MkdirAll(filepath.Join(storeRoot, "generations"), 0o700)).To(Succeed())
		sub, err := substrate.New("store", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		rep, err := buildAttestationReport(sub, "user", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(rep.GeneratedFrom.Generations).To(Equal([]int{}))
		Expect(rep.Packages).To(Equal([]schema.PackageEvidence{}))
		b, err := json.Marshal(rep)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(b)).To(ContainSubstring(`"packages":[]`))
		Expect(string(b)).To(ContainSubstring(`"generations":[]`))
	})

	// A generation an interrupted apply left without a manifest holds no
	// recorded evidence. The report skips it and names it, rather than failing
	// the whole audit until gc removes it.
	Context("with an incomplete or damaged generation", func() {
		const complete = `{
  "schema":"polypkg.manifest/v2","generation":%d,"scope":"user",
  "produced_by":{"tool":"polypkg","version":"0.1.0","timestamp":"2026-01-01T00:00:00Z","host":"test"},
  "entries":[{"name":"alpha","version":"1.0.0","content_hash":"blake3:a"}]}`
		var storeRoot string

		BeforeEach(func() {
			dir := sandboxUserEnv(GinkgoTB())
			storeRoot = filepath.Join(dir, "data", "polypkg")
			writeReportGen(storeRoot, 1, fmt.Sprintf(complete, 1))
			// generations/2: the skeleton BeginTransaction leaves, no manifest.
			Expect(os.MkdirAll(filepath.Join(storeRoot, "generations", "2", "active"), 0o700)).To(Succeed())
			writeReportGen(storeRoot, 3, fmt.Sprintf(complete, 3))
			Expect(os.Symlink(filepath.Join("generations", "3", "active"), filepath.Join(storeRoot, "active"))).To(Succeed())
		})

		runReport := func(args ...string) (string, string, error) {
			var stdout, stderr bytes.Buffer
			root := NewRootCmd()
			root.SetArgs(append([]string{"attestation", "report"}, args...))
			root.SetOut(&stdout)
			root.SetErr(&stderr)
			err := root.Execute()
			return stdout.String(), stderr.String(), err
		}

		It("skips it, reports the others, and records it as skipped", func() {
			sub, err := substrate.New("store", storeRoot)
			Expect(err).NotTo(HaveOccurred())
			rep, err := buildAttestationReport(sub, "user", storeRoot)
			Expect(err).NotTo(HaveOccurred())
			Expect(rep.GeneratedFrom.Generations).To(Equal([]int{1, 3}))
			Expect(rep.GeneratedFrom.SkippedIncomplete).To(Equal([]int{2}))
			Expect(rep.Packages).To(HaveLen(2))

			b, err := json.Marshal(rep)
			Expect(err).NotTo(HaveOccurred())
			_, err = schema.ParseAttestationReport(bytes.NewReader(b))
			Expect(err).NotTo(HaveOccurred(), "the report must satisfy its own schema: %s", b)
		})

		It("lists skipped generations in the JSON document", func() {
			stdout, _, err := runReport("--format", "json")
			Expect(err).NotTo(HaveOccurred())
			got, err := schema.ParseAttestationReport(strings.NewReader(stdout))
			Expect(err).NotTo(HaveOccurred(), stdout)
			Expect(got.GeneratedFrom.SkippedIncomplete).To(Equal([]int{2}))
		})

		It("notes skipped generations on stderr in text mode", func() {
			stdout, stderr, err := runReport()
			Expect(err).NotTo(HaveOccurred())
			Expect(stdout).To(ContainSubstring("2 generation(s)"))
			Expect(stdout).NotTo(ContainSubstring("skipped"))
			Expect(stderr).To(ContainSubstring("warning: skipped incomplete generation(s) 2"))
			Expect(stderr).To(ContainSubstring("polypkg gc"))
		})

		It("still fails when a manifest exists but cannot be read", func() {
			if os.Getuid() == 0 {
				Skip("root reads a mode-000 file, so the read error cannot be provoked")
			}
			manifest := filepath.Join(storeRoot, "generations", "1", "manifest.json")
			Expect(os.Chmod(manifest, 0)).To(Succeed())
			DeferCleanup(func() { _ = os.Chmod(manifest, 0o600) })

			sub, err := substrate.New("store", storeRoot)
			Expect(err).NotTo(HaveOccurred())
			_, err = buildAttestationReport(sub, "user", storeRoot)
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, substrate.ErrIncompleteGeneration)).To(BeFalse())
			Expect(errors.Is(err, fs.ErrPermission)).To(BeTrue(), "got %v", err)
			var cliErr *CLIError
			Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
			Expect(cliErr.Msg).To(Equal("cannot read generation 1's manifest"))
		})

		// A damaged manifest means corruption or tampering, not a crash.
		// Skipping it would let tampering hide a generation from the audit.
		It("fails, naming the generation, when a manifest is damaged", func() {
			Expect(os.WriteFile(filepath.Join(storeRoot, "generations", "1", "manifest.json"), []byte("garbage"), 0o600)).To(Succeed())

			for _, args := range [][]string{{}, {"--format", "json"}} {
				stdout, _, err := runReport(args...)
				Expect(err).To(HaveOccurred(), "args %v: the report must not succeed: %s", args, stdout)
				var cliErr *CLIError
				Expect(errors.As(err, &cliErr)).To(BeTrue(), "args %v: expected *CLIError, got %T: %v", args, err, err)
				Expect(cliErr.Msg).To(ContainSubstring("generation 1's manifest is damaged"), "args %v", args)
				Expect(cliErr.Hint).To(ContainSubstring(filepath.Join(storeRoot, "generations", "1")), "args %v", args)
				Expect(cliErr.Hint).NotTo(ContainSubstring("polypkg gc"), "args %v", args)
				Expect(errors.Is(cliErr.Err, substrate.ErrDamagedGeneration)).To(BeTrue(), "args %v", args)
			}
		})
	})
})
