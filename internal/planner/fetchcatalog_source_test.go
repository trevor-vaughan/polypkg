package planner_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// withAcceptExpiryUntil returns a copy of src with AcceptExpiryUntil set to
// deadline — used by the freshness-grace specs to opt one source into
// accept_expiry_until without mutating the profile's other source config.
func withAcceptExpiryUntil(src schema.SourceBackend, deadline string) schema.SourceBackend {
	src.AcceptExpiryUntil = deadline
	return src
}

// buildSignedLocalRepo builds a real signed polypkg repo containing one package
// (hello 1.0.0, serial 1) served from a local directory, honoring opts (e.g.
// SkipAttestations for the unattested-publish scenarios). It returns the output
// directory (used as the source URL) and the path to its trust_root.pub.
// testing.TB so both plain tests and Ginkgo specs (via GinkgoTB()) can call it.
func buildSignedLocalRepo(t testing.TB, sourceName string, opts repo.BuildOptions) (outputDir, trustRoot string) {
	t.Helper()
	outputDir, trustRoot, _ = buildSignedLocalRepoWithKeypair(t, sourceName, opts, nil)
	return outputDir, trustRoot
}

// buildSignedLocalRepoDecorated is buildSignedLocalRepo with an optional hook to
// mutate the package source dir (pkgs/hello) after layout but before the build —
// used to add carried attestations for carriage tests.
func buildSignedLocalRepoDecorated(t testing.TB, sourceName string, opts repo.BuildOptions, decorate func(t testing.TB, pkgDir string)) (outputDir, trustRoot string) {
	t.Helper()
	outputDir, trustRoot, _ = buildSignedLocalRepoWithKeypair(t, sourceName, opts, decorate)
	return outputDir, trustRoot
}

// buildSignedLocalRepoWithKeypair is buildSignedLocalRepoDecorated but also
// returns the repo's signing keypair, needed by specs that sign additional
// out-of-band documents (trust bundle, revocation list) with the same key the
// repo's trust_root anchors.
func buildSignedLocalRepoWithKeypair(t testing.TB, sourceName string, opts repo.BuildOptions, decorate func(t testing.TB, pkgDir string)) (outputDir, trustRoot string, kp *repo.Keypair) {
	t.Helper()
	root := t.TempDir()
	keyDir := t.TempDir() // outside the output dir (guardKeyNotInOutput)

	pkgDir := filepath.Join(root, "pkgs", "hello")
	if err := os.MkdirAll(filepath.Join(pkgDir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "polypkg.yaml"),
		[]byte("schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "content", "bin", "hello"),
		[]byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	kp, err := repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "repo.key")
	if err := repo.SaveKey(keyPath, kp, "pw", repo.KDFScrypt); err != nil {
		t.Fatal(err)
	}

	manifest := "schema: polypkg.repo/v1\nsource: " + sourceName + "\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    source: ./pkgs/hello\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	if decorate != nil {
		decorate(t, pkgDir)
	}
	if _, err := b.Build(opts); err != nil {
		t.Fatalf("Build: %v", err)
	}

	outputDir = filepath.Join(root, "public")
	trustRoot = filepath.Join(outputDir, "trust_root.pub")
	return outputDir, trustRoot, kp
}

// profileForLocalSource returns a minimal profile whose single source points at
// a local repo and requests the hello package in the user scope.
func profileForLocalSource(name, url, trustRoot string) *schema.Profile {
	return &schema.Profile{
		Schema: "polypkg.spec/v1",
		Name:   "t",
		Scopes: map[string]schema.ScopeSpec{"user": {Substrate: "store"}},
		Sources: schema.SourcesSpec{
			Order: []string{name},
			Sources: map[string]schema.SourceBackend{
				name: {Type: "polypkg-native", URL: url, TrustRoot: trustRoot},
			},
		},
		Packages: map[string]map[string]schema.PackageRef{
			"user": {"hello": {Version: ">=1.0.0"}},
		},
	}
}

func TestFetchCatalogVerifiesSignedLocalSource(t *testing.T) {
	out, tr := buildSignedLocalRepo(t, "repo", repo.BuildOptions{})
	p := profileForLocalSource("repo", out, tr)
	stateHome := t.TempDir()

	res, err := planner.FetchCatalog(context.Background(), p, planner.Options{Scope: "user", StateHome: stateHome})
	if err != nil {
		t.Fatalf("FetchCatalog on a valid signed source: %v", err)
	}
	if res.Catalog == nil {
		t.Fatal("expected a non-nil catalog")
	}
	if res.Keyrings["repo"] == nil {
		t.Fatal("expected a verified keyring for source repo")
	}

	// The trust and index serial high-water marks must advance to the published
	// serial (1) on success.
	seen, err := trust.LoadSeen(stateHome, "repo")
	if err != nil {
		t.Fatal(err)
	}
	if seen.TrustSerial != 1 || seen.IndexSerial != 1 {
		t.Fatalf("seen serials = trust %d index %d, want 1/1", seen.TrustSerial, seen.IndexSerial)
	}
}

func TestFetchCatalogRejectsTrustRollback(t *testing.T) {
	out, tr := buildSignedLocalRepo(t, "repo", repo.BuildOptions{})
	p := profileForLocalSource("repo", out, tr)
	stateHome := t.TempDir()

	// Pre-seed a trust serial higher than the repo publishes (1): a mirror
	// replaying this older trust document must be rejected.
	if err := trust.StoreSeen(stateHome, "repo", trust.Seen{TrustSerial: 5, IndexSerial: 5}); err != nil {
		t.Fatal(err)
	}
	_, err := planner.FetchCatalog(context.Background(), p, planner.Options{Scope: "user", StateHome: stateHome})
	if err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("want trust rollback rejection, got %v", err)
	}
}

func TestFetchCatalogRejectsIndexRollback(t *testing.T) {
	out, tr := buildSignedLocalRepo(t, "repo", repo.BuildOptions{})
	p := profileForLocalSource("repo", out, tr)
	stateHome := t.TempDir()

	// Trust serial within bounds, but a higher last-seen index serial than the
	// repo publishes (1): the stale index must be rejected even though its
	// trust document verifies.
	if err := trust.StoreSeen(stateHome, "repo", trust.Seen{TrustSerial: 0, IndexSerial: 5}); err != nil {
		t.Fatal(err)
	}
	_, err := planner.FetchCatalog(context.Background(), p, planner.Options{Scope: "user", StateHome: stateHome})
	if err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("want index rollback rejection, got %v", err)
	}
}

// writeBundle writes a signed polypkg.trust-bundle/v1 document (and its
// detached minisign signature) into repoDir, as a source's out-of-band bundle
// publish step would. kp must be the same keypair that signed the repo's
// trust_root (buildSignedLocalRepoWithKeypair's third return).
func writeBundle(repoDir string, kp *repo.Keypair, source string, serial uint64, expires string) {
	GinkgoHelper()
	writeBundleWithKeys(repoDir, kp, source, serial, expires, nil)
}

// writeBundleWithKeys writes a signed polypkg.trust-bundle/v1 carrying keys.
func writeBundleWithKeys(repoDir string, kp *repo.Keypair, source string, serial uint64, expires string, keys []schema.BuilderKey) {
	GinkgoHelper()
	b := schema.TrustBundle{Schema: "polypkg.trust-bundle/v1", Source: source, Serial: serial, Expires: expires, BuilderKeys: keys}
	raw, err := json.Marshal(b)
	Expect(err).NotTo(HaveOccurred())
	sig := kp.SignTrustBundle(serial, raw)
	Expect(os.WriteFile(filepath.Join(repoDir, "trust-bundle.json"), raw, 0o644)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(repoDir, "trust-bundle.json.minisig"), []byte(sig), 0o644)).To(Succeed())
}

// writeBundleWithSigstoreRoots writes a signed polypkg.trust-bundle/v1 carrying
// mirrored sigstore trust roots (the source-mirrored root chain 2c-3 shipped),
// so a full-Plan spec can prove a consumer pin overrides the mirrored root.
func writeBundleWithSigstoreRoots(repoDir string, kp *repo.Keypair, source string, serial uint64, expires string, roots []schema.SigstoreRoot) {
	GinkgoHelper()
	b := schema.TrustBundle{Schema: "polypkg.trust-bundle/v1", Source: source, Serial: serial, Expires: expires, SigstoreRoots: roots}
	raw, err := json.Marshal(b)
	Expect(err).NotTo(HaveOccurred())
	sig := kp.SignTrustBundle(serial, raw)
	Expect(os.WriteFile(filepath.Join(repoDir, "trust-bundle.json"), raw, 0o644)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(repoDir, "trust-bundle.json.minisig"), []byte(sig), 0o644)).To(Succeed())
}

// writeRevocations is writeBundle's counterpart for polypkg.revocation-list/v1.
func writeRevocations(repoDir string, kp *repo.Keypair, source string, serial uint64, expires string, atts []string) {
	GinkgoHelper()
	writeRevocationsFull(repoDir, kp, source, serial, expires, nil, atts)
}

// writeRevocationsFull writes a signed polypkg.revocation-list/v1 revoking both
// builder keys and attestation hashes.
func writeRevocationsFull(repoDir string, kp *repo.Keypair, source string, serial uint64, expires string, keys, atts []string) {
	GinkgoHelper()
	rl := schema.RevocationList{Schema: "polypkg.revocation-list/v1", Source: source, Serial: serial, Expires: expires, RevokedBuilderKeys: keys, RevokedAttestations: atts}
	raw, err := json.Marshal(rl)
	Expect(err).NotTo(HaveOccurred())
	sig := kp.SignRevocationList(serial, raw)
	Expect(os.WriteFile(filepath.Join(repoDir, "revocations.json"), raw, 0o644)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(repoDir, "revocations.json.minisig"), []byte(sig), 0o644)).To(Succeed())
}

var _ = Describe("FetchCatalog trust bundle + revocation list (2c-0)", func() {
	const src = "repo"
	far := "2099-01-01T00:00:00Z"

	// newHarness builds a fresh signed local repo (source name "repo") and a
	// matching profile/opts pair against a fresh state home, and returns the
	// served repo directory (where a spec can additionally drop
	// trust-bundle.json/revocations.json) and the repo's signing keypair.
	newHarness := func() (repoDir string, kp *repo.Keypair, prof *schema.Profile, opts planner.Options) {
		out, tr, key := buildSignedLocalRepoWithKeypair(GinkgoTB(), src, repo.BuildOptions{}, nil)
		return out, key, profileForLocalSource(src, out, tr), planner.Options{Scope: "user", StateHome: GinkgoT().TempDir()}
	}

	It("absent bundle & revocation on a never-seen source install cleanly and persist serial 0", func() {
		_, _, prof, opts := newHarness()
		fr, err := planner.FetchCatalog(GinkgoT().Context(), prof, opts)
		Expect(err).NotTo(HaveOccurred())
		Expect(fr.Revocations[src]).To(BeNil())
		seen, _ := trust.LoadSeen(opts.StateHome, src)
		Expect(seen.BundleSerial).To(Equal(uint64(0)))
		Expect(seen.RevocationSerial).To(Equal(uint64(0)))
	})

	It("loads a present bundle+revocation and advances the persisted floors", func() {
		repoDir, kp, prof, opts := newHarness()
		writeBundle(repoDir, kp, src, 3, far)
		writeRevocations(repoDir, kp, src, 2, far, nil)
		fr, err := planner.FetchCatalog(GinkgoT().Context(), prof, opts)
		Expect(err).NotTo(HaveOccurred())
		Expect(fr.Revocations[src]).NotTo(BeNil())
		seen, _ := trust.LoadSeen(opts.StateHome, src)
		Expect(seen.BundleSerial).To(Equal(uint64(3)))
		Expect(seen.RevocationSerial).To(Equal(uint64(2)))
	})

	It("refuses a bundle that vanished after being seen (rollback/strip)", func() {
		_, _, prof, opts := newHarness()
		Expect(trust.StoreSeen(opts.StateHome, src, trust.Seen{BundleSerial: 3})).To(Succeed())
		_, err := planner.FetchCatalog(GinkgoT().Context(), prof, opts)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("trust bundle"))
	})

	It("refuses a bundle whose serial rolled back below the floor", func() {
		repoDir, kp, prof, opts := newHarness()
		Expect(trust.StoreSeen(opts.StateHome, src, trust.Seen{BundleSerial: 5})).To(Succeed())
		writeBundle(repoDir, kp, src, 4, far)
		_, err := planner.FetchCatalog(GinkgoT().Context(), prof, opts)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("rollback"))
	})

	It("refuses an expired revocation list", func() {
		repoDir, kp, prof, opts := newHarness()
		writeRevocations(repoDir, kp, src, 1, "2000-01-01T00:00:00Z", nil)
		_, err := planner.FetchCatalog(GinkgoT().Context(), prof, opts)
		Expect(err).To(HaveOccurred())
	})

	It("flags a still-valid revocation list within the near-expiry window and persists its expires", func() {
		repoDir, kp, prof, opts := newHarness()
		soon := time.Now().Add(3 * 24 * time.Hour).UTC().Format(time.RFC3339)
		writeRevocations(repoDir, kp, src, 1, soon, nil)
		opts.RevocationNearExpiry = 14 * 24 * time.Hour
		fr, err := planner.FetchCatalog(GinkgoT().Context(), prof, opts)
		Expect(err).NotTo(HaveOccurred())
		Expect(fr.NearExpiry).To(HaveLen(1))
		Expect(fr.NearExpiry[0]).To(And(
			HaveField("Source", Equal(src)),
			HaveField("What", Equal("revocation list")),
			HaveField("Expires", Equal(soon)),
		))
		seen, err := trust.LoadSeen(opts.StateHome, src)
		Expect(err).NotTo(HaveOccurred())
		Expect(seen.RevocationExpires).To(Equal(soon))
	})

	It("does not flag a comfortably-fresh revocation list but still persists its expires", func() {
		repoDir, kp, prof, opts := newHarness()
		later := time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339)
		writeRevocations(repoDir, kp, src, 1, later, nil)
		opts.RevocationNearExpiry = 14 * 24 * time.Hour
		fr, err := planner.FetchCatalog(GinkgoT().Context(), prof, opts)
		Expect(err).NotTo(HaveOccurred())
		Expect(fr.NearExpiry).To(BeEmpty())
		seen, err := trust.LoadSeen(opts.StateHome, src)
		Expect(err).NotTo(HaveOccurred())
		Expect(seen.RevocationExpires).To(Equal(later))
	})

	It("keeps a present bundle on FetchResult.Bundles", func() {
		repoDir, kp, prof, opts := newHarness()
		writeBundle(repoDir, kp, src, 3, far)
		fr, err := planner.FetchCatalog(GinkgoT().Context(), prof, opts)
		Expect(err).NotTo(HaveOccurred())
		Expect(fr.Bundles[src]).NotTo(BeNil())
	})

	It("leaves FetchResult.Bundles nil for a source with no bundle", func() {
		_, _, prof, opts := newHarness()
		fr, err := planner.FetchCatalog(GinkgoT().Context(), prof, opts)
		Expect(err).NotTo(HaveOccurred())
		Expect(fr.Bundles[src]).To(BeNil())
	})
})

var _ = Describe("FetchCatalog accept_expiry_until freshness grace (2e-1)", func() {
	var restore func()
	AfterEach(func() {
		if restore != nil {
			restore()
			restore = nil
		}
	})

	It("reports freshness grace when metadata is expired but within accept_expiry_until", func() {
		out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{})
		p := profileForLocalSource("repo", out, tr)
		// Grace ceiling far in the future; jump the clock well past the index's
		// 720h validity so it is expired-but-graced.
		p.Sources.Sources["repo"] = withAcceptExpiryUntil(p.Sources.Sources["repo"],
			"2999-01-01T00:00:00Z")
		restore = trust.SetTimeNowForTesting(func() time.Time {
			return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
		})

		fr, err := planner.FetchCatalog(GinkgoT().Context(), p, planner.Options{Scope: "user", StateHome: GinkgoT().TempDir()})
		Expect(err).NotTo(HaveOccurred())
		Expect(fr.FreshnessGraced).NotTo(BeEmpty())
		Expect(fr.FreshnessGraced).To(ContainElement(And(
			HaveField("Source", Equal("repo")),
			HaveField("What", Equal("index")),
			HaveField("AcceptUntil", Equal("2999-01-01T00:00:00Z")),
		)))
	})

	It("refuses expired metadata when no accept_expiry_until is set", func() {
		out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{})
		p := profileForLocalSource("repo", out, tr)
		restore = trust.SetTimeNowForTesting(func() time.Time {
			return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
		})
		_, err := planner.FetchCatalog(GinkgoT().Context(), p, planner.Options{Scope: "user", StateHome: GinkgoT().TempDir()})
		Expect(err).To(MatchError(ContainSubstring("expired")))
	})

	It("persists a grace marker in Seen when metadata is graced", func() {
		out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{})
		p := profileForLocalSource("repo", out, tr)
		p.Sources.Sources["repo"] = withAcceptExpiryUntil(p.Sources.Sources["repo"], "2999-01-01T00:00:00Z")
		restore = trust.SetTimeNowForTesting(func() time.Time {
			return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
		})
		stateHome := GinkgoT().TempDir()
		_, err := planner.FetchCatalog(GinkgoT().Context(), p, planner.Options{Scope: "user", StateHome: stateHome})
		Expect(err).NotTo(HaveOccurred())
		seen, err := trust.LoadSeen(stateHome, "repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(seen.Graced).NotTo(BeNil())
		Expect(seen.Graced.AcceptUntil).To(Equal("2999-01-01T00:00:00Z"))
		Expect(seen.Graced.Docs).To(ContainElement("index"))
	})

	It("leaves the Seen grace marker nil when nothing is graced", func() {
		out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{})
		p := profileForLocalSource("repo", out, tr)
		stateHome := GinkgoT().TempDir()
		_, err := planner.FetchCatalog(GinkgoT().Context(), p, planner.Options{Scope: "user", StateHome: stateHome})
		Expect(err).NotTo(HaveOccurred())
		seen, err := trust.LoadSeen(stateHome, "repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(seen.Graced).To(BeNil())
	})
})

var _ = Describe("FetchCatalog persists revoked builder keys (revoked-builder status flag)", func() {
	const far = "2099-01-01T00:00:00Z"

	It("records the source's revoked builder keys in Seen", func() {
		priv, keyEntry := builderKeyFixture("builder-a")
		out, tr, kp := buildSignedCarriageRepoWith(GinkgoTB(), "repo", func(sha string) []byte {
			return signedSLSAEnvelope("bin/hello", sha, "builder-a", priv)
		})
		writeBundleWithKeys(out, kp, "repo", 1, far, []schema.BuilderKey{keyEntry})
		writeRevocationsFull(out, kp, "repo", 1, far, []string{"builder-a"}, nil)
		p := profileForLocalSource("repo", out, tr)
		stateHome := GinkgoT().TempDir()

		_, err := planner.FetchCatalog(GinkgoT().Context(), p, planner.Options{Scope: "user", StateHome: stateHome})
		Expect(err).NotTo(HaveOccurred())
		seen, err := trust.LoadSeen(stateHome, "repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(seen.RevokedBuilderKeys).To(Equal([]string{"builder-a"}))
	})

	It("records no revoked builder keys when the source has no revocation list", func() {
		priv, keyEntry := builderKeyFixture("builder-a")
		out, tr, kp := buildSignedCarriageRepoWith(GinkgoTB(), "repo", func(sha string) []byte {
			return signedSLSAEnvelope("bin/hello", sha, "builder-a", priv)
		})
		writeBundleWithKeys(out, kp, "repo", 1, far, []schema.BuilderKey{keyEntry})
		p := profileForLocalSource("repo", out, tr)
		stateHome := GinkgoT().TempDir()

		_, err := planner.FetchCatalog(GinkgoT().Context(), p, planner.Options{Scope: "user", StateHome: stateHome})
		Expect(err).NotTo(HaveOccurred())
		seen, err := trust.LoadSeen(stateHome, "repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(seen.RevokedBuilderKeys).To(BeEmpty())
	})
})

var _ = Describe("FetchCatalog persists revoked attestation hashes (revoked-attestation status flag)", func() {
	const far = "2099-01-01T00:00:00Z"

	It("records the source's revoked attestation hashes in Seen", func() {
		out, tr, kp := buildSignedLocalRepoWithKeypair(GinkgoTB(), "repo", repo.BuildOptions{}, nil)
		writeRevocationsFull(out, kp, "repo", 1, far, nil, []string{"blake3:e2ea11"})
		p := profileForLocalSource("repo", out, tr)
		stateHome := GinkgoT().TempDir()

		_, err := planner.FetchCatalog(GinkgoT().Context(), p, planner.Options{Scope: "user", StateHome: stateHome})
		Expect(err).NotTo(HaveOccurred())
		seen, err := trust.LoadSeen(stateHome, "repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(seen.RevokedAttestations).To(ContainElement("blake3:e2ea11"))
	})

	It("records no revoked attestation hashes when the source has no revocation list", func() {
		out, tr, _ := buildSignedLocalRepoWithKeypair(GinkgoTB(), "repo", repo.BuildOptions{}, nil)
		p := profileForLocalSource("repo", out, tr)
		stateHome := GinkgoT().TempDir()

		_, err := planner.FetchCatalog(GinkgoT().Context(), p, planner.Options{Scope: "user", StateHome: stateHome})
		Expect(err).NotTo(HaveOccurred())
		seen, err := trust.LoadSeen(stateHome, "repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(seen.RevokedAttestations).To(BeEmpty())
	})
})
