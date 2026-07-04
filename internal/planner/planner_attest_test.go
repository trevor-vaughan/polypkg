package planner_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/extractstore"
	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// readPublishedIndex parses the built repo's signed index so tests can compare
// the recorded attestation verdict against the published AttestationRef.
func readPublishedIndex(t testing.TB, outputDir string) *schema.Index {
	t.Helper()
	f, err := os.Open(filepath.Join(outputDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	idx, err := schema.ParseIndex(f)
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

// tamperAttestation flips one byte inside the published pool .att.json so the
// attestation signature (and content address) no longer verify.
func tamperAttestation(t testing.TB, outputDir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(outputDir, "pool", "*.att.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly one pool attestation, found %d", len(matches))
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-2] ^= 0x01
	if err := os.WriteFile(matches[0], data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// dsseSLSAEnvelope builds a DSSE envelope wrapping an in-toto SLSA provenance
// Statement whose single subject (advisory name subjectName) carries the given
// bare-hex sha256 digest. It mirrors the shape the repo package's carriage tests
// use; the builder/DSSE signature is unchecked at this phase (binding only).
func dsseSLSAEnvelope(subjectName, sha256hex string) []byte {
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"name": subjectName, "digest": map[string]string{"sha256": sha256hex}}},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate":     map[string]any{},
	}
	stB, _ := json.Marshal(st)
	env := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(stB),
		"signatures":  []map[string]string{{"keyid": "k", "sig": "AA=="}},
	}
	b, _ := json.Marshal(env)
	return b
}

// buildSignedCarriageRepo builds a signed local repo whose hello package carries
// an external DSSE-wrapped SLSA attestation binding the bin/hello content file by
// digest. Used to prove the consumer install-time binding (phase 2b-3).
func buildSignedCarriageRepo(t testing.TB, sourceName string) (outputDir, trustRoot string) {
	t.Helper()
	return buildSignedLocalRepoDecorated(t, sourceName, repo.BuildOptions{}, func(t testing.TB, pkgDir string) {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(pkgDir, "content", "bin", "hello"))
		if err != nil {
			t.Fatalf("read carriage fixture content: %v", err)
		}
		sum := sha256.Sum256(body)
		attDir := filepath.Join(pkgDir, "attestations")
		if err := os.MkdirAll(attDir, 0o755); err != nil {
			t.Fatal(err)
		}
		env := dsseSLSAEnvelope("bin/hello", hex.EncodeToString(sum[:]))
		if err := os.WriteFile(filepath.Join(attDir, "slsa.json"), env, 0o644); err != nil {
			t.Fatal(err)
		}
	})
}

var _ = Describe("Plan attestation policy gate", func() {
	planOpts := func(policy string) planner.Options {
		return planner.Options{
			Scope:             "user",
			DataHome:          GinkgoT().TempDir(),
			StateHome:         GinkgoT().TempDir(),
			AttestationPolicy: policy,
		}
	}

	Context("attested repo (publisher default)", func() {
		It("verifies and records the verdict under the default (warn) policy", func() {
			out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{})
			ref := readPublishedIndex(GinkgoTB(), out).Packages["hello"][0].Attestations[0]
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts(""))
			Expect(err).NotTo(HaveOccurred())
			Expect(res.AttestationWarnings).To(BeEmpty())
			Expect(res.Manifest.Entries).To(HaveLen(1))
			att := res.Manifest.Entries[0].Attestation
			Expect(att).NotTo(BeNil())
			Expect(att.Status).To(Equal("verified"))
			Expect(att.PredicateTypes).To(ConsistOf(attest.PredicateTypeSARIF))
			Expect(att.AttestationHash).To(Equal(ref.ContentHash))
			Expect(att.PolicyAtInstall).To(Equal("warn"))
		})

		It("verifies under require", func() {
			out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{})
			p := profileForLocalSource("repo", out, tr)
			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("require"))
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Manifest.Entries[0].Attestation.Status).To(Equal("verified"))
			Expect(res.Manifest.Entries[0].Attestation.PolicyAtInstall).To(Equal("require"))
		})
	})

	Context("unattested repo (--skip-attestations)", func() {
		It("installs with a warning and records unattested under warn", func() {
			out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{SkipAttestations: true})
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred())
			Expect(res.AttestationWarnings).To(HaveLen(1))
			Expect(res.AttestationWarnings[0]).To(ContainSubstring("hello-1.0.0 is not attested"))
			att := res.Manifest.Entries[0].Attestation
			Expect(att).NotTo(BeNil())
			Expect(att.Status).To(Equal("unattested"))
			Expect(att.PredicateTypes).To(BeEmpty())
			Expect(att.AttestationHash).To(BeEmpty())
			Expect(att.PolicyAtInstall).To(Equal("warn"))
		})

		It("refuses under require, naming the package and policy", func() {
			out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{SkipAttestations: true})
			p := profileForLocalSource("repo", out, tr)

			_, err := planner.Plan(GinkgoT().Context(), p, planOpts("require"))
			Expect(err).To(MatchError(ContainSubstring("hello-1.0.0")))
			Expect(err).To(MatchError(ContainSubstring("no attestation")))
			Expect(err).To(MatchError(ContainSubstring("require")))
		})

		It("installs silently and records unattested under off", func() {
			out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{SkipAttestations: true})
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("off"))
			Expect(err).NotTo(HaveOccurred())
			Expect(res.AttestationWarnings).To(BeEmpty())
			att := res.Manifest.Entries[0].Attestation
			Expect(att).NotTo(BeNil())
			Expect(att.Status).To(Equal("unattested"))
			Expect(att.PolicyAtInstall).To(Equal("off"))
		})
	})

	Context("carriage-published repo (external provenance)", func() {
		It("installs, verifies the native chain, and records the carried ref bound", func() {
			out, tr := buildSignedCarriageRepo(GinkgoTB(), "repo")
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Manifest.Entries).To(HaveLen(1))

			att := res.Manifest.Entries[0].Attestation
			Expect(att).NotTo(BeNil())
			// Native SARIF + polypkg-link still verify.
			Expect(att.Status).To(Equal("verified"))
			// The carried external provenance is bound to the installed bytes and
			// recorded at the bound-unverified tier (builder-signature verification
			// is phase 2c) — NOT silently skipped.
			Expect(att.CarriedBindings).To(HaveLen(1))
			Expect(att.CarriedBindings[0].Tier).To(Equal(schema.CarriedTierBoundUnverified))
			Expect(att.CarriedBindings[0].Format).To(Equal(schema.FormatSLSAProvenance))
			Expect(att.CarriedBindings[0].SubjectScope).To(Equal("content:bin/hello"))
		})
	})

	Context("present-but-tampered attestation (D-C10)", func() {
		// A present attestation must hard-verify in EVERY policy mode — the
		// policy setting only governs absence.
		for _, policy := range []string{"warn", "require", "off"} {
			It("hard-fails under policy "+policy+" without leaving an extracted tree", func() {
				out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{})
				tamperAttestation(GinkgoTB(), out)
				p := profileForLocalSource("repo", out, tr)

				opts := planOpts(policy)
				_, err := planner.Plan(GinkgoT().Context(), p, opts)
				Expect(err).To(MatchError(ContainSubstring("attestation")))
				Expect(err).To(MatchError(ContainSubstring("hello-1.0.0")))

				// Attestation verification runs BEFORE extraction: the refused
				// artifact must not leave its tree in the scratch area.
				hash := readPublishedIndex(GinkgoTB(), out).Packages["hello"][0].ContentHash
				Expect(extractstore.Dir(opts.StateHome, "hello", "1.0.0", hash)).NotTo(BeADirectory())
			})
		}
	})
})
