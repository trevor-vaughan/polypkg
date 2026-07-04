package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// makeStatusWeakState writes generation-1 substrate state whose manifest
// contains a normal package (hello) and a weak entry (extras, Weak=true,
// RecommendedBy=["app"]).
func makeStatusWeakState(storeRoot string) {
	gen1Dir := filepath.Join(storeRoot, "generations", "1", "active")
	Expect(os.MkdirAll(gen1Dir, 0o700)).To(Succeed())
	activeLink := filepath.Join(storeRoot, "active")
	Expect(os.Symlink(filepath.Join("generations", "1", "active"), activeLink)).To(Succeed())
	own := filepath.Join(storeRoot, "generations", "1", "ownership.json")
	Expect(os.WriteFile(own,
		[]byte(`{"schema":"polypkg.ownership/v1","scope":"user","entries":[]}`),
		0o600)).To(Succeed())
	manifest := filepath.Join(storeRoot, "generations", "1", "manifest.json")
	Expect(os.WriteFile(manifest, []byte(`{
  "schema": "polypkg.manifest/v2",
  "generation": 1,
  "scope": "user",
  "produced_by": {"tool":"polypkg","version":"0.1.0","timestamp":"2026-01-01T00:00:00Z","host":"test"},
  "entries": [
    {"name":"hello","version":"1.0.0","content_hash":"blake3:aabbcc"},
    {"name":"extras","version":"0.5.0","content_hash":"blake3:112233","weak":true,"recommended_by":["app"]}
  ]
}`), 0o600)).To(Succeed())
}

// makeStatusAttestState writes generation-1 substrate state whose manifest
// contains three packages spanning every attestation-record case: hello with a
// verified record, unatt with an unattested record, and legacy with no record
// at all (pre-v2 generation).
func makeStatusAttestState(storeRoot string) {
	gen1Dir := filepath.Join(storeRoot, "generations", "1", "active")
	Expect(os.MkdirAll(gen1Dir, 0o700)).To(Succeed())
	activeLink := filepath.Join(storeRoot, "active")
	Expect(os.Symlink(filepath.Join("generations", "1", "active"), activeLink)).To(Succeed())
	own := filepath.Join(storeRoot, "generations", "1", "ownership.json")
	Expect(os.WriteFile(own,
		[]byte(`{"schema":"polypkg.ownership/v1","scope":"user","entries":[]}`),
		0o600)).To(Succeed())
	manifest := filepath.Join(storeRoot, "generations", "1", "manifest.json")
	Expect(os.WriteFile(manifest, []byte(`{
  "schema": "polypkg.manifest/v2",
  "generation": 1,
  "scope": "user",
  "produced_by": {"tool":"polypkg","version":"0.1.0","timestamp":"2026-01-01T00:00:00Z","host":"test"},
  "entries": [
    {"name":"hello","version":"1.0.0","content_hash":"blake3:aabbcc",
     "attestation":{"status":"verified","predicate_types":["https://polypkg.dev/attestation/sarif/v1"],"attestation_hash":"blake3:445566","policy_at_install":"warn"}},
    {"name":"unatt","version":"2.0.0","content_hash":"blake3:ddeeff",
     "attestation":{"status":"unattested","policy_at_install":"warn"}},
    {"name":"legacy","version":"3.0.0","content_hash":"blake3:778899"}
  ]
}`), 0o600)).To(Succeed())
}

var _ = Describe("status command", func() {
	setup := func() {
		dir := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	}
	setupWithStore := func() (dir, storeRoot string) {
		dir = GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
		storeRoot = filepath.Join(dir, "data", "polypkg")
		return dir, storeRoot
	}

	It("prints an empty-state message and exits with nil when no generation has been applied", func() {
		setup()
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"status"})
		root.SetOut(&out)
		err := root.Execute()
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).To(ContainSubstring("no generation applied yet — apply a profile to get started"))
	})

	It("flags weak entries with [weak] tag under -vv", func() {
		_, storeRoot := setupWithStore()
		makeStatusWeakState(storeRoot)
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"status", "-vv"})
		root.SetOut(&out)
		err := root.Execute()
		Expect(err).NotTo(HaveOccurred())
		output := out.String()
		Expect(output).To(ContainSubstring("[weak]"),
			"weak entry must carry [weak] tag")
		Expect(output).To(ContainSubstring("recommended by app"),
			"weak entry must show recommending package")
	})

	It("does not show [weak] at default verbosity", func() {
		_, storeRoot := setupWithStore()
		makeStatusWeakState(storeRoot)
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"status"})
		root.SetOut(&out)
		err := root.Execute()
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).NotTo(ContainSubstring("[weak]"),
			"[weak] annotation must not appear at default verbosity — only under -vv")
	})

	It("renders the attestation state per entry under -vv", func() {
		_, storeRoot := setupWithStore()
		makeStatusAttestState(storeRoot)
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"status", "-vv"})
		root.SetOut(&out)
		err := root.Execute()
		Expect(err).NotTo(HaveOccurred())
		for _, line := range strings.Split(out.String(), "\n") {
			switch {
			case strings.Contains(line, "hello"):
				Expect(line).To(ContainSubstring("[attested]"),
					"verified entry must carry [attested]")
			case strings.Contains(line, "unatt"):
				Expect(line).To(ContainSubstring("[unattested]"),
					"unattested entry must carry [unattested]")
			case strings.Contains(line, "legacy"):
				Expect(line).NotTo(ContainSubstring("attested"),
					"entry without a record (pre-v2 generation) must have no attestation tag")
			}
		}
		Expect(out.String()).To(ContainSubstring("[attested]"), "the listing must have rendered")
	})

	It("does not show attestation tags at default verbosity", func() {
		_, storeRoot := setupWithStore()
		makeStatusAttestState(storeRoot)
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"status"})
		root.SetOut(&out)
		err := root.Execute()
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).NotTo(ContainSubstring("[attested]"),
			"attestation tags appear only under -vv")
	})

	It("does not annotate non-weak entries under -vv", func() {
		_, storeRoot := setupWithStore()
		makeStatusWeakState(storeRoot)
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"status", "-vv"})
		root.SetOut(&out)
		err := root.Execute()
		Expect(err).NotTo(HaveOccurred())
		output := out.String()
		// [weak] must appear somewhere — confirming the annotator ran at all.
		Expect(output).To(ContainSubstring("[weak]"), "[weak] must appear in output")
		// hello is a normal package; no line that mentions it may also carry [weak].
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, "hello") {
				Expect(line).NotTo(ContainSubstring("[weak]"), "non-weak entry line must not carry [weak]")
			}
		}
	})
})
