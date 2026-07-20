package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"

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
		rep, err := buildAttestationReport(sub, "user")
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
		rep2, err := buildAttestationReport(sub, "user")
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
		rep, err := buildAttestationReport(sub, "user")
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
		rep, err := buildAttestationReport(sub, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(rep.GeneratedFrom.Generations).To(Equal([]int{}))
		Expect(rep.Packages).To(Equal([]schema.PackageEvidence{}))
		b, err := json.Marshal(rep)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(b)).To(ContainSubstring(`"packages":[]`))
		Expect(string(b)).To(ContainSubstring(`"generations":[]`))
	})
})
