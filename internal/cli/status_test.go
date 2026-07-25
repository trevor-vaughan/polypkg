package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
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

func writeSeenForTest(t *testing.T, stateHome, source string, s trust.Seen) {
	t.Helper()
	if err := trust.StoreSeen(stateHome, source, s); err != nil {
		t.Fatalf("StoreSeen(%s): %v", source, err)
	}
}

func TestCollectRevocationFreshnessClassifies(t *testing.T) {
	stateHome := t.TempDir()
	now := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	rfc := func(tm time.Time) string { return tm.UTC().Format(time.RFC3339) }
	writeSeenForTest(t, stateHome, "fresh", trust.Seen{RevocationSerial: 1, RevocationExpires: rfc(now.Add(90 * 24 * time.Hour))})
	writeSeenForTest(t, stateHome, "near", trust.Seen{RevocationSerial: 1, RevocationExpires: rfc(now.Add(3 * 24 * time.Hour))})
	writeSeenForTest(t, stateHome, "exp-unack", trust.Seen{RevocationSerial: 1, RevocationExpires: rfc(now.Add(-10 * 24 * time.Hour))})
	writeSeenForTest(t, stateHome, "exp-ack", trust.Seen{
		RevocationSerial: 1, RevocationExpires: rfc(now.Add(-10 * 24 * time.Hour)),
		Graced: &trust.SeenGrace{AcceptUntil: rfc(now.Add(30 * 24 * time.Hour)), Docs: []string{trust.DocRevocationList}},
	})
	// Defensive branches: never-fetched (empty expires) and malformed expires are
	// both skipped silently rather than erroring.
	writeSeenForTest(t, stateHome, "no-rev", trust.Seen{RevocationSerial: 1})
	writeSeenForTest(t, stateHome, "bad-rev", trust.Seen{RevocationSerial: 1, RevocationExpires: "garbage"})
	// A near-expiry source that is ALSO graced must NOT pick up acknowledgement:
	// the grace gate is scoped to expired entries only.
	writeSeenForTest(t, stateHome, "near-graced", trust.Seen{
		RevocationSerial: 1, RevocationExpires: rfc(now.Add(3 * 24 * time.Hour)),
		Graced: &trust.SeenGrace{AcceptUntil: rfc(now.Add(30 * 24 * time.Hour)), Docs: []string{trust.DocRevocationList}},
	})
	got, err := collectRevocationFreshness(stateHome, 14*24*time.Hour, now)
	if err != nil {
		t.Fatalf("collectRevocationFreshness: %v", err)
	}
	bySrc := map[string]schema.StatusRevocationFreshness{}
	for _, e := range got {
		bySrc[e.Source] = e
	}
	if _, ok := bySrc["fresh"]; ok {
		t.Fatalf("fresh should be omitted: %+v", bySrc["fresh"])
	}
	if _, ok := bySrc["no-rev"]; ok {
		t.Fatalf("empty RevocationExpires should be omitted: %+v", bySrc["no-rev"])
	}
	if _, ok := bySrc["bad-rev"]; ok {
		t.Fatalf("malformed RevocationExpires should be omitted: %+v", bySrc["bad-rev"])
	}
	if bySrc["near"].State != "near_expiry" {
		t.Fatalf("near.State = %q", bySrc["near"].State)
	}
	if e := bySrc["near-graced"]; e.State != "near_expiry" || e.Acknowledged {
		t.Fatalf("near-graced must be near_expiry and unacknowledged: %+v", e)
	}
	if e := bySrc["exp-unack"]; e.State != "expired" || e.Acknowledged {
		t.Fatalf("exp-unack = %+v", e)
	}
	if e := bySrc["exp-ack"]; e.State != "expired" || !e.Acknowledged {
		t.Fatalf("exp-ack = %+v", e)
	}
}

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

func TestCollectRevokedAttestationsMatches(t *testing.T) {
	m := &schema.Manifest{Entries: []schema.ManifestEntry{{
		Name: "acme", Version: "1.0.0",
		Attestation: &schema.AttestationState{CarriedBindings: []schema.CarriedBinding{
			{Tier: schema.CarriedTierBuilderVerified, AttestationHash: "blake3:aa"},
			{Tier: schema.CarriedTierVerifiedTransportOnly, AttestationHash: "blake3:bb"},
			{Tier: schema.CarriedTierBoundUnverified, AttestationHash: ""}, // old/empty: never matches
		}},
	}}}
	revoked := map[string]struct{}{"blake3:aa": {}, "blake3:bb": {}}
	got := collectRevokedAttestations(m, revoked)
	if len(got) != 2 {
		t.Fatalf("want 2 hits, got %+v", got)
	}
	if got[0].AttestationHash != "blake3:aa" || got[1].AttestationHash != "blake3:bb" {
		t.Fatalf("order/hashes = %+v", got)
	}
	if none := collectRevokedAttestations(m, map[string]struct{}{}); len(none) != 0 {
		t.Fatalf("empty set must match nothing: %+v", none)
	}
}

func TestCollectRevokedAttestationsEmptyHashGuardAndNilAttestation(t *testing.T) {
	m := &schema.Manifest{Entries: []schema.ManifestEntry{
		{Name: "acme", Version: "1.0.0", Attestation: &schema.AttestationState{CarriedBindings: []schema.CarriedBinding{
			{Tier: schema.CarriedTierBoundUnverified, AttestationHash: ""}, // empty hash
		}}},
		{Name: "beta", Version: "2.0.0", Attestation: nil}, // nil attestation must be skipped, not panic
	}}
	// Revoked set even CONTAINS "" — the guard, not a set-miss, must exclude it.
	got := collectRevokedAttestations(m, map[string]struct{}{"": {}})
	if len(got) != 0 {
		t.Fatalf("empty-hash binding must never match even when \"\" is revoked; got %+v", got)
	}
}
