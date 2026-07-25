package planner_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
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

// paeTest builds the DSSE PAE independently of production code (test oracle).
func paeTest(payloadType string, body []byte) []byte {
	out := []byte("DSSEv1 ")
	out = append(out, []byte(strconv.Itoa(len(payloadType)))...)
	out = append(out, ' ')
	out = append(out, []byte(payloadType)...)
	out = append(out, ' ')
	out = append(out, []byte(strconv.Itoa(len(body)))...)
	out = append(out, ' ')
	out = append(out, body...)
	return out
}

// signedSLSAEnvelope is dsseSLSAEnvelope but with a real ed25519 signature over
// the DSSE PAE, labelled keyID — the builder-verified fixture for 2c-1a.
func signedSLSAEnvelope(subjectName, sha256hex, keyID string, priv ed25519.PrivateKey) []byte {
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"name": subjectName, "digest": map[string]string{"sha256": sha256hex}}},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate":     map[string]any{},
	}
	body, _ := json.Marshal(st)
	sig := ed25519.Sign(priv, paeTest("application/vnd.in-toto+json", body))
	env := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(body),
		"signatures":  []map[string]string{{"keyid": keyID, "sig": base64.StdEncoding.EncodeToString(sig)}},
	}
	b, _ := json.Marshal(env)
	return b
}

// buildSignedCarriageRepoWith builds a carriage repo whose hello package carries
// a DSSE-wrapped SLSA envelope produced by envFor(sha256hex) (bare-hex sha256 of
// content/bin/hello). Returns output dir, trust root, and repo keypair (to sign
// an out-of-band trust bundle / revocation list).
func buildSignedCarriageRepoWith(t testing.TB, sourceName string, envFor func(sha256hex string) []byte) (outputDir, trustRoot string, kp *repo.Keypair) {
	t.Helper()
	return buildSignedLocalRepoWithKeypair(t, sourceName, repo.BuildOptions{}, func(t testing.TB, pkgDir string) {
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
		if err := os.WriteFile(filepath.Join(attDir, "slsa.json"), envFor(hex.EncodeToString(sum[:])), 0o644); err != nil {
			t.Fatal(err)
		}
	})
}

// builderKeyFixture generates an ed25519 builder key and the schema.BuilderKey
// entry (open-ended window; 2c-1a does not check the window) a bundle carries.
func builderKeyFixture(keyID string) (priv ed25519.PrivateKey, entry schema.BuilderKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	Expect(err).NotTo(HaveOccurred())
	return priv, schema.BuilderKey{
		KeyID:     keyID,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Algo:      "ed25519",
		ValidFrom: "2000-01-01T00:00:00Z",
	}
}

// builderKeyFixtureWindow is builderKeyFixture with an explicit validity window,
// so the 2c-1b build-timestamp gate can be exercised in-window vs out-of-window.
func builderKeyFixtureWindow(keyID, validFrom, validUntil string) (priv ed25519.PrivateKey, entry schema.BuilderKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	Expect(err).NotTo(HaveOccurred())
	return priv, schema.BuilderKey{
		KeyID:      keyID,
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		Algo:       "ed25519",
		ValidFrom:  validFrom,
		ValidUntil: validUntil,
	}
}

// signedSLSAEnvelopeMeta is signedSLSAEnvelope but embeds a real SLSA predicate
// carrying builderID + finishedOn at the version-specific path for predicateType,
// and signs the DSSE PAE with priv under keyID — the 2c-1b fixture proving
// builder_identity extraction and the build-timestamp window gate.
func signedSLSAEnvelopeMeta(subjectName, sha256hex, keyID string, priv ed25519.PrivateKey, predicateType, builderID, finishedOn string) []byte {
	var predicate map[string]any
	switch predicateType {
	case "https://slsa.dev/provenance/v1":
		predicate = map[string]any{
			"buildDefinition": map[string]any{"buildType": "https://example.com/build"},
			"runDetails": map[string]any{
				"builder":  map[string]any{"id": builderID},
				"metadata": map[string]any{"finishedOn": finishedOn},
			},
		}
	case "https://slsa.dev/provenance/v0.2":
		predicate = map[string]any{
			"builder":   map[string]any{"id": builderID},
			"buildType": "https://example.com/build",
			"metadata":  map[string]any{"buildFinishedOn": finishedOn},
		}
	default:
		predicate = map[string]any{}
	}
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"name": subjectName, "digest": map[string]string{"sha256": sha256hex}}},
		"predicateType": predicateType,
		"predicate":     predicate,
	}
	body, _ := json.Marshal(st)
	sig := ed25519.Sign(priv, paeTest("application/vnd.in-toto+json", body))
	env := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(body),
		"signatures":  []map[string]string{{"keyid": keyID, "sig": base64.StdEncoding.EncodeToString(sig)}},
	}
	b, _ := json.Marshal(env)
	return b
}

// rawSPDXEnvelope is a bare (unwrapped, unsigned) SPDX document whose only file
// checksum is the sha256 of content/bin/hello — the raw-SBOM fixture proving the
// verified-transport-only tier.
func rawSPDXEnvelope(sha256hex string) []byte {
	doc := map[string]any{
		"spdxVersion": "SPDX-2.3",
		"SPDXID":      "SPDXRef-DOCUMENT",
		"name":        "hello-sbom",
		"files": []map[string]any{{
			"fileName":  "bin/hello",
			"SPDXID":    "SPDXRef-File-hello",
			"checksums": []map[string]any{{"algorithm": "SHA256", "checksumValue": sha256hex}},
		}},
	}
	b, _ := json.Marshal(doc)
	return b
}

// rawCycloneDXEnvelope is a bare CycloneDX BOM whose described component's hash is
// the sha256 of content/bin/hello.
func rawCycloneDXEnvelope(sha256hex string) []byte {
	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"metadata": map[string]any{
			"component": map[string]any{
				"type":   "application",
				"name":   "hello",
				"hashes": []map[string]any{{"alg": "SHA-256", "content": sha256hex}},
			},
		},
	}
	b, _ := json.Marshal(doc)
	return b
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
			// The carried envelope is DSSE-wrapped but no trust bundle is published,
			// so its builder signature cannot be verified: honest transport-only
			// state (2c-1a), digest-bound but builder-unverified — NOT builder-verified.
			Expect(att.CarriedBindings).To(HaveLen(1))
			Expect(att.CarriedBindings[0].Tier).To(Equal(schema.CarriedTierVerifiedTransportOnly))
			Expect(att.CarriedBindings[0].Format).To(Equal(schema.FormatSLSAProvenance))
			Expect(att.CarriedBindings[0].SubjectScope).To(Equal("content:bin/hello"))
			Expect(att.CarriedBindings[0].VerifyingKeyID).To(BeEmpty())
		})

		It("records the carried attestation's content-hash on the binding", func() {
			out, tr := buildSignedCarriageRepo(GinkgoTB(), "repo")
			// Find the carried ref's published content-hash so we can assert the
			// binding records exactly that value (the offline revocation key, 2c-0).
			var carriedHash string
			for _, ref := range readPublishedIndex(GinkgoTB(), out).Packages["hello"][0].Attestations {
				if ref.Kind == schema.KindCarriedOpaque {
					carriedHash = ref.ContentHash
				}
			}
			Expect(carriedHash).NotTo(BeEmpty())
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred())
			b := res.Manifest.Entries[0].Attestation.CarriedBindings
			Expect(b).To(HaveLen(1))
			Expect(b[0].AttestationHash).To(Equal(carriedHash))
		})
	})

	Context("carriage builder-signature verification (2c-1a)", func() {
		far := "2099-01-01T00:00:00Z"

		It("records builder-verified with the key id when a bundle key signs the envelope", func() {
			priv, keyEntry := builderKeyFixture("builder-a")
			out, tr, kp := buildSignedCarriageRepoWith(GinkgoTB(), "repo", func(sha string) []byte {
				return signedSLSAEnvelope("bin/hello", sha, "builder-a", priv)
			})
			writeBundleWithKeys(out, kp, "repo", 1, far, []schema.BuilderKey{keyEntry})
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred())
			b := res.Manifest.Entries[0].Attestation.CarriedBindings
			Expect(b).To(HaveLen(1))
			Expect(b[0].Tier).To(Equal(schema.CarriedTierBuilderVerified))
			Expect(b[0].VerifyingKeyID).To(Equal("builder-a"))
		})

		It("records verified-transport-only when the signing key is not in the bundle", func() {
			priv, _ := builderKeyFixture("builder-a")
			_, otherEntry := builderKeyFixture("builder-other")
			out, tr, kp := buildSignedCarriageRepoWith(GinkgoTB(), "repo", func(sha string) []byte {
				return signedSLSAEnvelope("bin/hello", sha, "builder-a", priv)
			})
			writeBundleWithKeys(out, kp, "repo", 1, far, []schema.BuilderKey{otherEntry})
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred())
			b := res.Manifest.Entries[0].Attestation.CarriedBindings
			Expect(b).To(HaveLen(1))
			Expect(b[0].Tier).To(Equal(schema.CarriedTierVerifiedTransportOnly))
			Expect(b[0].VerifyingKeyID).To(BeEmpty())
		})

		It("downgrades to verified-transport-only and still installs when the builder key is revoked", func() {
			priv, keyEntry := builderKeyFixture("builder-a")
			out, tr, kp := buildSignedCarriageRepoWith(GinkgoTB(), "repo", func(sha string) []byte {
				return signedSLSAEnvelope("bin/hello", sha, "builder-a", priv)
			})
			writeBundleWithKeys(out, kp, "repo", 1, far, []schema.BuilderKey{keyEntry})
			writeRevocationsFull(out, kp, "repo", 1, far, []string{"builder-a"}, nil)
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred()) // revoked BUILDER key downgrades, never refuses (unlike a revoked attestation)
			b := res.Manifest.Entries[0].Attestation.CarriedBindings
			Expect(b).To(HaveLen(1))
			Expect(b[0].Tier).To(Equal(schema.CarriedTierVerifiedTransportOnly))
			Expect(b[0].VerifyingKeyID).To(BeEmpty())
		})
	})

	Context("carriage predicate interpretation (2c-1b)", func() {
		far := "2099-01-01T00:00:00Z"

		It("stays builder-verified and records builder_identity when the key was in window at build time", func() {
			priv, keyEntry := builderKeyFixtureWindow("builder-a", "2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z")
			out, tr, kp := buildSignedCarriageRepoWith(GinkgoTB(), "repo", func(sha string) []byte {
				return signedSLSAEnvelopeMeta("bin/hello", sha, "builder-a", priv,
					"https://slsa.dev/provenance/v1", "https://ci/acme", "2024-06-01T00:00:00Z")
			})
			writeBundleWithKeys(out, kp, "repo", 1, far, []schema.BuilderKey{keyEntry})
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred())
			b := res.Manifest.Entries[0].Attestation.CarriedBindings
			Expect(b).To(HaveLen(1))
			Expect(b[0].Tier).To(Equal(schema.CarriedTierBuilderVerified))
			Expect(b[0].VerifyingKeyID).To(Equal("builder-a"))
			Expect(b[0].BuilderIdentity).To(Equal("https://ci/acme"))
		})

		It("downgrades to verified-transport-only when the key was out of window at build time", func() {
			priv, keyEntry := builderKeyFixtureWindow("builder-a", "2020-01-01T00:00:00Z", "2023-01-01T00:00:00Z")
			out, tr, kp := buildSignedCarriageRepoWith(GinkgoTB(), "repo", func(sha string) []byte {
				return signedSLSAEnvelopeMeta("bin/hello", sha, "builder-a", priv,
					"https://slsa.dev/provenance/v1", "https://ci/acme", "2024-06-01T00:00:00Z")
			})
			writeBundleWithKeys(out, kp, "repo", 1, far, []schema.BuilderKey{keyEntry})
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred()) // out-of-window downgrades, never refuses
			b := res.Manifest.Entries[0].Attestation.CarriedBindings
			Expect(b).To(HaveLen(1))
			Expect(b[0].Tier).To(Equal(schema.CarriedTierVerifiedTransportOnly))
			Expect(b[0].VerifyingKeyID).To(BeEmpty())
			Expect(b[0].BuilderIdentity).To(BeEmpty())
		})

		It("records builder_identity from the SLSA v0.2 path", func() {
			priv, keyEntry := builderKeyFixtureWindow("builder-a", "2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z")
			out, tr, kp := buildSignedCarriageRepoWith(GinkgoTB(), "repo", func(sha string) []byte {
				return signedSLSAEnvelopeMeta("bin/hello", sha, "builder-a", priv,
					"https://slsa.dev/provenance/v0.2", "https://ci/v02", "2024-06-01T00:00:00Z")
			})
			writeBundleWithKeys(out, kp, "repo", 1, far, []schema.BuilderKey{keyEntry})
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred())
			b := res.Manifest.Entries[0].Attestation.CarriedBindings
			Expect(b).To(HaveLen(1))
			Expect(b[0].Tier).To(Equal(schema.CarriedTierBuilderVerified))
			Expect(b[0].BuilderIdentity).To(Equal("https://ci/v02"))
		})

		It("stays builder-verified with a bounded-window key when the envelope carries no build timestamp (F1)", func() {
			priv, keyEntry := builderKeyFixtureWindow("builder-a", "2020-01-01T00:00:00Z", "2023-01-01T00:00:00Z")
			out, tr, kp := buildSignedCarriageRepoWith(GinkgoTB(), "repo", func(sha string) []byte {
				return signedSLSAEnvelope("bin/hello", sha, "builder-a", priv)
			})
			writeBundleWithKeys(out, kp, "repo", 1, far, []schema.BuilderKey{keyEntry})
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred())
			b := res.Manifest.Entries[0].Attestation.CarriedBindings
			Expect(b).To(HaveLen(1))
			Expect(b[0].Tier).To(Equal(schema.CarriedTierBuilderVerified))
			Expect(b[0].BuilderIdentity).To(BeEmpty()) // empty predicate ⇒ no builder.id
		})
	})

	Context("SBOM carriage (2c-2)", func() {
		far := "2099-01-01T00:00:00Z"

		It("reaches builder-verified for a DSSE-wrapped, builder-signed SPDX SBOM", func() {
			priv, keyEntry := builderKeyFixtureWindow("builder-a", "2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z")
			out, tr, kp := buildSignedCarriageRepoWith(GinkgoTB(), "repo", func(sha string) []byte {
				return signedSLSAEnvelopeMeta("bin/hello", sha, "builder-a", priv,
					"https://spdx.dev/Document", "", "")
			})
			writeBundleWithKeys(out, kp, "repo", 1, far, []schema.BuilderKey{keyEntry})
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred())
			b := res.Manifest.Entries[0].Attestation.CarriedBindings
			Expect(b).To(HaveLen(1))
			Expect(b[0].Format).To(Equal(schema.FormatSPDX))
			Expect(b[0].Tier).To(Equal(schema.CarriedTierBuilderVerified))
			Expect(b[0].VerifyingKeyID).To(Equal("builder-a"))
			Expect(b[0].BuilderIdentity).To(BeEmpty()) // SBOMs carry no SLSA builder.id
		})

		It("reaches builder-verified for a DSSE-wrapped, builder-signed CycloneDX SBOM", func() {
			priv, keyEntry := builderKeyFixtureWindow("builder-a", "2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z")
			out, tr, kp := buildSignedCarriageRepoWith(GinkgoTB(), "repo", func(sha string) []byte {
				return signedSLSAEnvelopeMeta("bin/hello", sha, "builder-a", priv,
					"https://cyclonedx.org/bom", "", "")
			})
			writeBundleWithKeys(out, kp, "repo", 1, far, []schema.BuilderKey{keyEntry})
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred())
			b := res.Manifest.Entries[0].Attestation.CarriedBindings
			Expect(b).To(HaveLen(1))
			Expect(b[0].Format).To(Equal(schema.FormatCycloneDX))
			Expect(b[0].Tier).To(Equal(schema.CarriedTierBuilderVerified))
		})

		It("records verified-transport-only for a raw SPDX SBOM and still installs", func() {
			_, keyEntry := builderKeyFixtureWindow("builder-a", "2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z")
			out, tr, kp := buildSignedCarriageRepoWith(GinkgoTB(), "repo", func(sha string) []byte {
				return rawSPDXEnvelope(sha)
			})
			writeBundleWithKeys(out, kp, "repo", 1, far, []schema.BuilderKey{keyEntry})
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred())
			b := res.Manifest.Entries[0].Attestation.CarriedBindings
			Expect(b).To(HaveLen(1))
			Expect(b[0].Format).To(Equal(schema.FormatSPDX))
			Expect(b[0].PredicateType).To(Equal("https://spdx.dev/Document"))
			Expect(b[0].Tier).To(Equal(schema.CarriedTierVerifiedTransportOnly))
			Expect(b[0].VerifyingKeyID).To(BeEmpty())
		})

		It("records verified-transport-only for a raw CycloneDX SBOM", func() {
			out, tr, kp := buildSignedCarriageRepoWith(GinkgoTB(), "repo", func(sha string) []byte {
				return rawCycloneDXEnvelope(sha)
			})
			writeBundleWithKeys(out, kp, "repo", 1, far, nil)
			p := profileForLocalSource("repo", out, tr)

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred())
			b := res.Manifest.Entries[0].Attestation.CarriedBindings
			Expect(b).To(HaveLen(1))
			Expect(b[0].Format).To(Equal(schema.FormatCycloneDX))
			Expect(b[0].Tier).To(Equal(schema.CarriedTierVerifiedTransportOnly))
		})
	})

	Context("revoked attestation (2c-0)", func() {
		far := "2099-01-01T00:00:00Z"

		It("refuses to install a package whose attestation content-hash is revoked", func() {
			out, tr, kp := buildSignedLocalRepoWithKeypair(GinkgoTB(), "repo", repo.BuildOptions{}, nil)
			hash := readPublishedIndex(GinkgoTB(), out).Packages["hello"][0].Attestations[0].ContentHash
			writeRevocations(out, kp, "repo", 1, far, []string{hash})
			p := profileForLocalSource("repo", out, tr)

			_, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("revoked"))
		})

		It("installs normally when the revocation list revokes an unrelated hash", func() {
			out, tr, kp := buildSignedLocalRepoWithKeypair(GinkgoTB(), "repo", repo.BuildOptions{}, nil)
			writeRevocations(out, kp, "repo", 1, far, []string{"blake3:deadbeef"})
			p := profileForLocalSource("repo", out, tr)

			_, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred())
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

	Context("per-source require gate (2d-1)", func() {
		// profileForLocalSource builds a native-source profile; we set the new
		// per-source Attestation block directly on the source struct.
		withRequire := func(out, tr string, pol *schema.SourceAttestationPolicy) *schema.Profile {
			p := profileForLocalSource("repo", out, tr)
			sb := p.Sources.Sources["repo"]
			sb.Attestation = pol
			p.Sources.Sources["repo"] = sb
			return p
		}

		It("installs when a required predicate is satisfied by the native attestation (empty allow-list)", func() {
			out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{})
			p := withRequire(out, tr, &schema.SourceAttestationPolicy{Require: []string{attest.PredicateTypeSARIF}})
			res, err := planner.Plan(GinkgoT().Context(), p, planOpts(""))
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Manifest.Entries).To(HaveLen(1))
			Expect(res.Manifest.Entries[0].Attestation.Status).To(Equal("verified"))
		})

		It("refuses when a required predicate is absent (G2: strip)", func() {
			out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{})
			p := withRequire(out, tr, &schema.SourceAttestationPolicy{Require: []string{"https://slsa.dev/provenance/v1"}})
			_, err := planner.Plan(GinkgoT().Context(), p, planOpts(""))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("required predicate"))
			Expect(err.Error()).To(ContainSubstring("https://slsa.dev/provenance/v1"))
		})
	})

	Context("posture floor (2d-2)", func() {
		It("refuses when a previously-verified predicate regresses, and the exact-version pin accepts it", func() {
			// apply1: an attested repo records the native SARIF predicate.
			out1, tr1 := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{})
			res1, err := planner.Plan(GinkgoT().Context(), profileForLocalSource("repo", out1, tr1), planOpts(""))
			Expect(err).NotTo(HaveOccurred())
			Expect(res1.Manifest.Entries[0].Attestation.PredicateTypes).To(ContainElement(attest.PredicateTypeSARIF))

			// apply2: the same package, now published WITHOUT attestations ⇒ SARIF regresses.
			out2, tr2 := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{SkipAttestations: true})
			p2 := profileForLocalSource("repo", out2, tr2)
			opts := planOpts("")
			opts.PriorManifest = res1.Manifest
			_, err = planner.Plan(GinkgoT().Context(), p2, opts)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("posture floor"))
			Expect(err.Error()).To(ContainSubstring(attest.PredicateTypeSARIF))

			// apply2 with the exact version pinned ⇒ the operator accepts the drop.
			p2.Packages["user"]["hello"] = schema.PackageRef{Version: "=1.0.0"}
			res2, err := planner.Plan(GinkgoT().Context(), p2, opts)
			Expect(err).NotTo(HaveOccurred())
			Expect(res2.Manifest.Entries[0].Attestation.Status).To(Equal("unattested"))
		})

		It("does not gate a package absent from the prior manifest (TOFU baseline)", func() {
			out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{SkipAttestations: true})
			opts := planOpts("")
			opts.PriorManifest = &schema.Manifest{} // empty prior ⇒ no floor
			_, err := planner.Plan(GinkgoT().Context(), profileForLocalSource("repo", out, tr), opts)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("per-source off (2d-3, G8)", func() {
		withTier := func(out, tr, tier string) *schema.Profile {
			p := profileForLocalSource("repo", out, tr)
			sb := p.Sources.Sources["repo"]
			sb.Attestation = &schema.SourceAttestationPolicy{Tier: tier}
			p.Sources.Sources["repo"] = sb
			return p
		}

		It("installs an unattested package from an off source even under global require, recording the disabled gate", func() {
			out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{SkipAttestations: true})
			p := withTier(out, tr, schema.AttestationTierOff)
			// Global policy require would normally REFUSE an unattested package;
			// per-source off overrides the absence gate for this source.
			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("require"))
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Manifest.Entries).To(HaveLen(1))
			Expect(res.AttestationGateDisabled).To(ContainElement(And(
				HaveField("Package", ContainSubstring("hello-1.0.0")),
				HaveField("Source", Equal("repo")),
			)))
			Expect(res.Manifest.Entries[0].Attestation.GateDisabled).To(BeTrue())
			Expect(res.Manifest.Entries[0].Attestation.Status).To(Equal("unattested"))
		})

		It("still hard-verifies a PRESENT attestation from an off source (D-C10 not bypassed)", func() {
			out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{})
			tamperAttestation(GinkgoTB(), out)
			p := withTier(out, tr, schema.AttestationTierOff)
			_, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).To(MatchError(ContainSubstring("attestation")))
			Expect(err).To(MatchError(ContainSubstring("hello-1.0.0")))
		})

		It("waives the posture floor for an off source (loudly)", func() {
			// apply1: attested (SARIF) via a normal source ⇒ records the floor.
			out1, tr1 := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{})
			res1, err := planner.Plan(GinkgoT().Context(), profileForLocalSource("repo", out1, tr1), planOpts(""))
			Expect(err).NotTo(HaveOccurred())
			Expect(res1.Manifest.Entries[0].Attestation.PredicateTypes).To(ContainElement(attest.PredicateTypeSARIF))

			// apply2: unattested via an OFF source + the prior manifest. Without
			// off the floor would refuse (see the 2d-2 test); off waives it, loudly.
			out2, tr2 := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{SkipAttestations: true})
			p2 := withTier(out2, tr2, schema.AttestationTierOff)
			opts := planOpts("")
			opts.PriorManifest = res1.Manifest
			res2, err := planner.Plan(GinkgoT().Context(), p2, opts)
			Expect(err).NotTo(HaveOccurred())
			Expect(res2.AttestationGateDisabled).NotTo(BeEmpty())
			Expect(res2.Manifest.Entries[0].Attestation.GateDisabled).To(BeTrue())
		})

		It("still refuses a REVOKED present attestation from an off source (revocation not bypassed)", func() {
			// off is a policy relaxation, not a verification bypass: a revoked
			// attestation content-hash refuses in every mode (2c-0), before the
			// present/absent policy split, so tier: off never reaches it. Closes the
			// spec §10.8 #7 / §11 G8 matrix row (previously covered only by code
			// structure — see the 2d-3 holistic review follow-up).
			out, tr, kp := buildSignedLocalRepoWithKeypair(GinkgoTB(), "repo", repo.BuildOptions{}, nil)
			hash := readPublishedIndex(GinkgoTB(), out).Packages["hello"][0].Attestations[0].ContentHash
			writeRevocations(out, kp, "repo", 1, "2099-01-01T00:00:00Z", []string{hash})
			p := withTier(out, tr, schema.AttestationTierOff)

			_, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("revoked"))
		})
	})

	// The consumer-pinned sigstore root (2e-5) is unit-tested at the bindCarriedRefs
	// half (planner_attest_whitebox_test.go) and at trust.SelectSigstoreRoot, but the
	// production wiring in Plan that READS profile SourceBackend.SigstoreRoot and threads
	// it into bindCarriedRefs (planner.go: `pinnedSigstoreRoot = sb.SigstoreRoot`) was
	// never exercised end to end: deleting it left every test green. This closes that gap.
	Context("consumer-pinned sigstore root (2e-5 profile→Plan wiring)", func() {
		readAttestFixture := func(name string) []byte {
			b, err := os.ReadFile(filepath.Join("..", "attest", "testdata", name))
			Expect(err).NotTo(HaveOccurred())
			return b
		}

		// buildSigstoreCarriageRepo builds a signed repo whose hello package's
		// content IS bindable-content.bin (so the sigstore bundle's inner in-toto
		// subject digest binds by digest) and carries bindable-bundle.json — the
		// same offline-verifiable fixture the whitebox tier tests consume.
		buildSigstoreCarriageRepo := func() (out, tr string, kp *repo.Keypair) {
			bundle := readAttestFixture("bindable-bundle.json")
			content := readAttestFixture("bindable-content.bin")
			return buildSignedLocalRepoWithKeypair(GinkgoTB(), "repo", repo.BuildOptions{}, func(t testing.TB, pkgDir string) {
				t.Helper()
				Expect(os.WriteFile(filepath.Join(pkgDir, "content", "bin", "hello"), content, 0o755)).To(Succeed())
				attDir := filepath.Join(pkgDir, "attestations")
				Expect(os.MkdirAll(attDir, 0o755)).To(Succeed())
				Expect(os.WriteFile(filepath.Join(attDir, "sig.json"), bundle, 0o644)).To(Succeed())
			})
		}

		It("Plan threads the profile pin: the pinned root verifies where the mirrored root cannot (mirror never consulted, G1)", func() {
			out, tr, kp := buildSigstoreCarriageRepo()
			// The source mirrors the WRONG CA (a different CA over the same window:
			// in-window so the kernel runs, but it never signed this bundle). The
			// consumer pins the RIGHT CA. If Plan threads the pin, the pin is
			// authoritative and verification succeeds ⇒ verified-offline. Delete the
			// pin wiring and Plan falls back to the mirrored wrong CA ⇒
			// verified-transport-only; consult the mirror despite the pin and the same.
			var wrongMirror schema.SigstoreRoot
			Expect(json.Unmarshal(readAttestFixture("unrelated-root.json"), &wrongMirror)).To(Succeed())
			var rightPin schema.SigstoreRoot
			Expect(json.Unmarshal(readAttestFixture("bindable-root.json"), &rightPin)).To(Succeed())
			writeBundleWithSigstoreRoots(out, kp, "repo", 1, "2099-01-01T00:00:00Z", []schema.SigstoreRoot{wrongMirror})

			p := profileForLocalSource("repo", out, tr)
			sb := p.Sources.Sources["repo"]
			sb.SigstoreRoot = &rightPin
			p.Sources.Sources["repo"] = sb

			res, err := planner.Plan(GinkgoT().Context(), p, planOpts("warn"))
			Expect(err).NotTo(HaveOccurred())
			b := res.Manifest.Entries[0].Attestation.CarriedBindings
			Expect(b).To(HaveLen(1))
			Expect(b[0].Tier).To(Equal(schema.CarriedTierVerifiedOffline))
			Expect(b[0].CertificateIdentity).NotTo(BeEmpty())
			Expect(b[0].CertificateIssuer).NotTo(BeEmpty())
		})
	})
})
