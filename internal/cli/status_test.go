package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
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
	writeGraceState := func(dir, source, acceptUntil string, docs []string) {
		trustDir := filepath.Join(dir, "state", "polypkg", "trust")
		Expect(os.MkdirAll(trustDir, 0o700)).To(Succeed())
		docsJSON, err := json.Marshal(docs)
		Expect(err).NotTo(HaveOccurred())
		body := `{"trust_serial":1,"index_serial":1,"graced":{"accept_until":"` + acceptUntil + `","docs":` + string(docsJSON) + `}}`
		Expect(os.WriteFile(filepath.Join(trustDir, source+".json"), []byte(body), 0o600)).To(Succeed())
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

	It("shows a freshness-grace count on the default summary line", func() {
		dir, storeRoot := setupWithStore()
		makeStatusWeakState(storeRoot)
		writeGraceState(dir, "repo", "2999-01-01T00:00:00Z", []string{"index"})
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"status"})
		root.SetOut(&out)
		Expect(root.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("grace: 1 source(s)"))
	})

	It("lists per-source graced docs and marks an expired window under -v", func() {
		dir, storeRoot := setupWithStore()
		makeStatusWeakState(storeRoot)
		writeGraceState(dir, "repo", "2000-01-01T00:00:00Z", []string{"index", "trust document"})
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"status", "-v"})
		root.SetOut(&out)
		Expect(root.Execute()).To(Succeed())
		output := out.String()
		Expect(output).To(ContainSubstring("freshness grace:"))
		Expect(output).To(ContainSubstring("repo: index, trust document"))
		Expect(output).To(ContainSubstring("accepted under grace until 2000-01-01T00:00:00Z"))
		Expect(output).To(ContainSubstring("[window EXPIRED]"))
	})

	It("does not mark a future grace window as expired", func() {
		dir, storeRoot := setupWithStore()
		makeStatusWeakState(storeRoot)
		writeGraceState(dir, "repo", "2999-01-01T00:00:00Z", []string{"index"})
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"status", "-v"})
		root.SetOut(&out)
		Expect(root.Execute()).To(Succeed())
		Expect(out.String()).NotTo(ContainSubstring("[window EXPIRED]"))
	})

	It("omits the grace segment entirely when no source is graced", func() {
		_, storeRoot := setupWithStore()
		makeStatusWeakState(storeRoot)
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"status"})
		root.SetOut(&out)
		Expect(root.Execute()).To(Succeed())
		Expect(out.String()).NotTo(ContainSubstring("grace:"))
	})

	makeStatusRevokedBuilderState := func(storeRoot string) {
		gen1Dir := filepath.Join(storeRoot, "generations", "1", "active")
		Expect(os.MkdirAll(gen1Dir, 0o700)).To(Succeed())
		Expect(os.Symlink(filepath.Join("generations", "1", "active"), filepath.Join(storeRoot, "active"))).To(Succeed())
		Expect(os.WriteFile(filepath.Join(storeRoot, "generations", "1", "ownership.json"),
			[]byte(`{"schema":"polypkg.ownership/v1","scope":"user","entries":[]}`), 0o600)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(storeRoot, "generations", "1", "manifest.json"), []byte(`{
  "schema":"polypkg.manifest/v2","generation":1,"scope":"user",
  "produced_by":{"tool":"polypkg","version":"0.1.0","timestamp":"2026-01-01T00:00:00Z","host":"test"},
  "entries":[
    {"name":"hello","version":"1.0.0","content_hash":"blake3:aabbcc",
     "attestation":{"status":"verified","policy_at_install":"warn",
       "carried_bindings":[{"predicate_type":"p","format":"f","subject_scope":"artifact","tier":"builder-verified","verifying_key_id":"builder-a"}]}}
  ]}`), 0o600)).To(Succeed())
	}
	writeRevokedKeyState := func(dir, source string, keys []string) {
		trustDir := filepath.Join(dir, "state", "polypkg", "trust")
		Expect(os.MkdirAll(trustDir, 0o700)).To(Succeed())
		keysJSON, err := json.Marshal(keys)
		Expect(err).NotTo(HaveOccurred())
		body := `{"trust_serial":1,"index_serial":1,"revoked_builder_keys":` + string(keysJSON) + `}`
		Expect(os.WriteFile(filepath.Join(trustDir, source+".json"), []byte(body), 0o600)).To(Succeed())
	}

	It("flags an installed package whose builder key is revoked (summary + exit code 3)", func() {
		dir, storeRoot := setupWithStore()
		makeStatusRevokedBuilderState(storeRoot)
		writeRevokedKeyState(dir, "repo", []string{"builder-a"})
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"status"})
		root.SetOut(&out)
		err := root.Execute()
		Expect(out.String()).To(ContainSubstring("revoked builders: 1 package(s)"))
		Expect(ExitCode(err)).To(Equal(3))
	})

	It("shows the revoked key id per package under -vv", func() {
		dir, storeRoot := setupWithStore()
		makeStatusRevokedBuilderState(storeRoot)
		writeRevokedKeyState(dir, "repo", []string{"builder-a"})
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"status", "-vv"})
		root.SetOut(&out)
		_ = root.Execute()
		Expect(out.String()).To(ContainSubstring("[builder revoked: builder-a]"))
	})

	It("emits revoked_builders in JSON and exits 3", func() {
		dir, storeRoot := setupWithStore()
		makeStatusRevokedBuilderState(storeRoot)
		writeRevokedKeyState(dir, "repo", []string{"builder-a"})
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"status", "--format", "json"})
		root.SetOut(&out)
		err := root.Execute()
		sr, perr := schema.ParseStatusResult(strings.NewReader(out.String()))
		Expect(perr).NotTo(HaveOccurred())
		Expect(sr.RevokedBuilders).To(HaveLen(1))
		Expect(sr.RevokedBuilders[0].Package).To(Equal("hello"))
		Expect(sr.RevokedBuilders[0].KeyID).To(Equal("builder-a"))
		Expect(ExitCode(err)).To(Equal(3))
	})

	It("does not flag when the builder key is not revoked (exit 0)", func() {
		dir, storeRoot := setupWithStore()
		makeStatusRevokedBuilderState(storeRoot)
		writeRevokedKeyState(dir, "repo", []string{"someone-else"})
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"status"})
		root.SetOut(&out)
		err := root.Execute()
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).NotTo(ContainSubstring("revoked builders:"))
	})
})

func TestAttestationTagGateOffAndCarriedTiers(t *testing.T) {
	// gate-off is prominent
	off := &schema.AttestationState{Status: "unattested", GateDisabled: true}
	if got := attestationTag(off); !strings.Contains(got, "gate OFF") {
		t.Errorf("gate-off state must flag the disabled gate, got %q", got)
	}
	// a verified entry with a weak carried tier must NOT read as fully trusted:
	// the transport-only tier is surfaced verbatim.
	weak := &schema.AttestationState{
		Status: "verified",
		CarriedBindings: []schema.CarriedBinding{
			{PredicateType: "slsa", Tier: schema.CarriedTierBuilderVerified},
			{PredicateType: "sbom", Tier: schema.CarriedTierVerifiedTransportOnly},
		},
	}
	got := attestationTag(weak)
	if !strings.Contains(got, "attested") {
		t.Errorf("verified entry must still say attested, got %q", got)
	}
	if !strings.Contains(got, schema.CarriedTierVerifiedTransportOnly) {
		t.Errorf("carried transport-only tier must be surfaced, got %q", got)
	}
	if !strings.Contains(got, schema.CarriedTierBuilderVerified) {
		t.Errorf("carried builder-verified tier must be surfaced, got %q", got)
	}
	// a plain verified entry with no carried bindings is unchanged
	if got := attestationTag(&schema.AttestationState{Status: "verified"}); got != " [attested]" {
		t.Errorf("plain verified tag changed: %q", got)
	}
	if got := attestationTag(nil); got != "" {
		t.Errorf("nil must yield empty tag, got %q", got)
	}
}
