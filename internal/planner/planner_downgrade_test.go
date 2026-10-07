package planner_test

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/platform"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// fixturePkg describes one package entry published into a rebuildable test
// repo: its version, its platform ("" for platform-agnostic; otherwise written
// as the recipe's platform: key), and an optional single hard dependency (for
// the resolver-chosen-dependency downgrade scenario).
type fixturePkg struct {
	Version      string
	Platform     string
	DependsName  string
	DependsRange string
}

// signedRepo is a rebuildable signed test repository. Unlike
// buildSignedLocalRepo (single fixed publish), Publish rewrites the package
// sources and the repo manifest, then rebuilds into the SAME output dir with
// the SAME key — so serials advance exactly like a real republish and
// downgrade/vanish scenarios can be driven as fetch sequences.
type signedRepo struct {
	tb      testing.TB
	root    string
	keyDir  string
	keyPath string
	source  string

	OutputDir string
	TrustRoot string
}

func newSignedRepo(tb testing.TB, sourceName string) *signedRepo {
	tb.Helper()
	root := tb.TempDir()
	keyDir := tb.TempDir() // outside the output dir (guardKeyNotInOutput)

	kp, err := repo.GenerateKeypair()
	if err != nil {
		tb.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "repo.key")
	if err := repo.SaveKey(keyPath, kp, "pw", repo.KDFScrypt); err != nil {
		tb.Fatal(err)
	}
	out := filepath.Join(root, "public")
	return &signedRepo{
		tb:        tb,
		root:      root,
		keyDir:    keyDir,
		keyPath:   keyPath,
		source:    sourceName,
		OutputDir: out,
		TrustRoot: filepath.Join(out, "trust_root.pub"),
	}
}

// Publish (re)writes the package sources and manifest for exactly pkgs (one
// entry per package), then builds. See PublishEntries.
func (r *signedRepo) Publish(opts repo.BuildOptions, pkgs map[string]fixturePkg) {
	r.tb.Helper()
	multi := make(map[string][]fixturePkg, len(pkgs))
	for name, spec := range pkgs {
		multi[name] = []fixturePkg{spec}
	}
	r.PublishEntries(opts, multi)
}

// PublishEntries (re)writes the package sources and manifest for exactly pkgs,
// one source directory per entry, then builds. Prior package source dirs are
// removed so a vanished package really disappears from the published index.
func (r *signedRepo) PublishEntries(opts repo.BuildOptions, pkgs map[string][]fixturePkg) {
	r.tb.Helper()
	pkgsRoot := filepath.Join(r.root, "pkgs")
	if err := os.RemoveAll(pkgsRoot); err != nil {
		r.tb.Fatal(err)
	}

	names := make([]string, 0, len(pkgs))
	for name := range pkgs {
		names = append(names, name)
	}
	sort.Strings(names)

	manifest := "schema: polypkg.repo/v1\nsource: " + r.source + "\noutput: ./public\n" +
		"key:\n  path: " + r.keyPath + "\n  kdf: scrypt\n" +
		"packages:\n"
	for _, name := range names {
		manifest += "  " + name + ":\n"
		for i, spec := range pkgs[name] {
			rel := name + "/" + strconv.Itoa(i)
			dir := filepath.Join(pkgsRoot, name, strconv.Itoa(i))
			if err := os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755); err != nil {
				r.tb.Fatal(err)
			}
			recipe := "schema: polypkg.package/v1\nname: " + name + "\nversion: " + spec.Version + "\n"
			if spec.Platform != "" {
				recipe += "platform: " + spec.Platform + "\n"
			}
			if spec.DependsName != "" {
				recipe += "depends:\n  - name: " + spec.DependsName + "\n    version: \"" + spec.DependsRange + "\"\n"
			}
			recipe += "actions: []\n"
			if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(recipe), 0o644); err != nil {
				r.tb.Fatal(err)
			}
			// Version- and platform-dependent content so every entry has distinct bytes.
			if err := os.WriteFile(filepath.Join(dir, "content", "bin", name),
				[]byte("#!/bin/sh\necho "+name+" "+spec.Version+" "+spec.Platform+"\n"), 0o755); err != nil {
				r.tb.Fatal(err)
			}
			manifest += "    - source: ./pkgs/" + rel + "\n"
		}
	}

	mPath := filepath.Join(r.root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		r.tb.Fatal(err)
	}
	b, err := repo.NewBuilder(mPath, r.keyDir, "pw")
	if err != nil {
		r.tb.Fatalf("NewBuilder: %v", err)
	}
	if _, err := b.Build(opts); err != nil {
		r.tb.Fatalf("Build: %v", err)
	}
}

// foreignPlatform returns a producer-valid platform that is never this host,
// so a fixture can publish an entry the host must not select.
func foreignPlatform() string {
	if platform.Host() == "darwin/arm64" {
		return "linux/amd64"
	}
	return "darwin/arm64"
}

// profileWithConstraints returns a user-scope profile against one source with
// the given package -> version-constraint set.
func profileWithConstraints(name, url, trustRoot string, pkgs map[string]string) *schema.Profile {
	refs := map[string]schema.PackageRef{}
	for pkg, ver := range pkgs {
		refs[pkg] = schema.PackageRef{Version: ver}
	}
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
		Packages: map[string]map[string]schema.PackageRef{"user": refs},
	}
}

var _ = Describe("Plan per-package anti-downgrade (D15)", func() {
	planOpts := func(stateHome string) planner.Options {
		return planner.Options{Scope: "user", DataHome: GinkgoT().TempDir(), StateHome: stateHome}
	}

	It("refuses resolving below the high-water mark unless the profile pins the exact version", func() {
		r := newSignedRepo(GinkgoTB(), "repo")
		r.Publish(repo.BuildOptions{}, map[string]fixturePkg{"hello": {Version: "2.0.0"}})
		stateHome := GinkgoT().TempDir()

		ranged := profileWithConstraints("repo", r.OutputDir, r.TrustRoot, map[string]string{"hello": ">=1.0.0"})
		res, err := planner.Plan(GinkgoT().Context(), ranged, planOpts(stateHome))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Manifest.Entries[0].Version).To(Equal("2.0.0"))

		// The source now offers only an older version — a mirror downgrade trick.
		r.Publish(repo.BuildOptions{}, map[string]fixturePkg{"hello": {Version: "1.9.0"}})
		_, err = planner.Plan(GinkgoT().Context(), ranged, planOpts(stateHome))
		Expect(err).To(MatchError(ContainSubstring("refusing to downgrade hello to 1.9.0")))
		Expect(err).To(MatchError(ContainSubstring("previously offered 2.0.0")))
		Expect(err).To(MatchError(ContainSubstring("pin the exact version")))

		// Exact pins are the operator's escape hatch — bare and "=" forms.
		for _, pin := range []string{"1.9.0", "=1.9.0"} {
			pinned := profileWithConstraints("repo", r.OutputDir, r.TrustRoot, map[string]string{"hello": pin})
			res, err = planner.Plan(GinkgoT().Context(), pinned, planOpts(stateHome))
			Expect(err).NotTo(HaveOccurred(), "pin %q must accept the downgrade", pin)
			Expect(res.Manifest.Entries[0].Version).To(Equal("1.9.0"))
		}
	})

	It("allows the lower version against a fresh state home (no HWM recorded)", func() {
		r := newSignedRepo(GinkgoTB(), "repo")
		r.Publish(repo.BuildOptions{}, map[string]fixturePkg{"hello": {Version: "1.9.0"}})
		p := profileWithConstraints("repo", r.OutputDir, r.TrustRoot, map[string]string{"hello": ">=1.0.0"})

		res, err := planner.Plan(GinkgoT().Context(), p, planOpts(GinkgoT().TempDir()))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Manifest.Entries[0].Version).To(Equal("1.9.0"))
	})

	It("keeps the HWM when the package vanishes from the index, refusing its older reappearance", func() {
		r := newSignedRepo(GinkgoTB(), "repo")
		stateHome := GinkgoT().TempDir()

		r.Publish(repo.BuildOptions{}, map[string]fixturePkg{"hello": {Version: "2.0.0"}})
		hello := profileWithConstraints("repo", r.OutputDir, r.TrustRoot, map[string]string{"hello": ">=1.0.0"})
		_, err := planner.Plan(GinkgoT().Context(), hello, planOpts(stateHome))
		Expect(err).NotTo(HaveOccurred())

		// hello vanishes entirely; fetching the hello-less index must not drop
		// its recorded high-water mark.
		r.Publish(repo.BuildOptions{}, map[string]fixturePkg{"other": {Version: "1.0.0"}})
		other := profileWithConstraints("repo", r.OutputDir, r.TrustRoot, map[string]string{"other": ">=1.0.0"})
		_, err = planner.Plan(GinkgoT().Context(), other, planOpts(stateHome))
		Expect(err).NotTo(HaveOccurred())
		seen, err := trust.LoadSeen(stateHome, "repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(seen.HighWater(platform.Host())).To(HaveKeyWithValue("hello", "2.0.0"))
		Expect(seen.HighWater(platform.Host())).To(HaveKeyWithValue("other", "1.0.0"))

		// hello reappears older: still refused.
		r.Publish(repo.BuildOptions{}, map[string]fixturePkg{"hello": {Version: "1.9.0"}})
		_, err = planner.Plan(GinkgoT().Context(), hello, planOpts(stateHome))
		Expect(err).To(MatchError(ContainSubstring("refusing to downgrade hello to 1.9.0")))
	})

	It("does not advance stored serials or HWMs when a validly-signed index fails catalog construction", func() {
		r := newSignedRepo(GinkgoTB(), "repo")
		stateHome := GinkgoT().TempDir()
		p := profileWithConstraints("repo", r.OutputDir, r.TrustRoot, map[string]string{"hello": ">=1.0.0"})

		r.Publish(repo.BuildOptions{}, map[string]fixturePkg{"hello": {Version: "1.0.0"}})
		_, err := planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).NotTo(HaveOccurred())
		before, err := trust.LoadSeen(stateHome, "repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(before.IndexSerial).To(BeNumerically(">", 0))

		// Republish with a non-semver version. Signing and serial bumping are
		// publisher-side mechanics that do not parse versions, so the index is
		// validly signed at a higher serial — but BuildCatalog refuses it. The
		// refusal must not persist the higher serials: otherwise the consumer
		// is wedged rejecting every replayed good index as a rollback until
		// the publisher reaches an even higher serial.
		r.Publish(repo.BuildOptions{}, map[string]fixturePkg{"hello": {Version: "not-semver"}})
		_, err = planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).To(MatchError(ContainSubstring("build catalog")))

		after, err := trust.LoadSeen(stateHome, "repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before))
	})

	It("refuses a resolver-chosen dependency below the HWM (no profile entry, so no pin applies)", func() {
		r := newSignedRepo(GinkgoTB(), "repo")
		stateHome := GinkgoT().TempDir()
		p := profileWithConstraints("repo", r.OutputDir, r.TrustRoot, map[string]string{"hello": ">=1.0.0"})

		r.Publish(repo.BuildOptions{}, map[string]fixturePkg{
			"hello": {Version: "1.0.0", DependsName: "lib", DependsRange: ">=1.0.0"},
			"lib":   {Version: "2.0.0"},
		})
		res, err := planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).NotTo(HaveOccurred())
		versions := map[string]string{}
		for _, e := range res.Manifest.Entries {
			versions[e.Name] = e.Version
		}
		Expect(versions).To(HaveKeyWithValue("lib", "2.0.0"))

		// The dependency is republished older; hello itself is unchanged.
		r.Publish(repo.BuildOptions{}, map[string]fixturePkg{
			"hello": {Version: "1.0.0", DependsName: "lib", DependsRange: ">=1.0.0"},
			"lib":   {Version: "1.9.0"},
		})
		_, err = planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).To(MatchError(ContainSubstring("refusing to downgrade lib to 1.9.0")))
	})
})

var _ = Describe("Plan on a multi-platform index", func() {
	planOpts := func(stateHome string) planner.Options {
		return planner.Options{Scope: "user", DataHome: GinkgoT().TempDir(), StateHome: stateHome}
	}

	It("installs this host's 1.x when 2.0 is published only for another platform, recording 1.x as the high-water mark", func() {
		r := newSignedRepo(GinkgoTB(), "repo")
		r.PublishEntries(repo.BuildOptions{}, map[string][]fixturePkg{"hello": {
			{Version: "1.0.0", Platform: platform.Host()},
			{Version: "2.0.0", Platform: foreignPlatform()},
		}})
		stateHome := GinkgoT().TempDir()
		p := profileWithConstraints("repo", r.OutputDir, r.TrustRoot, map[string]string{"hello": ">=1.0.0"})

		res, err := planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Manifest.Entries).To(HaveLen(1))
		Expect(res.Manifest.Entries[0].Version).To(Equal("1.0.0"))

		seen, err := trust.LoadSeen(stateHome, "repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(seen.HighWater(platform.Host())).To(HaveKeyWithValue("hello", "1.0.0"))

		// Re-planning against the recorded state is not a downgrade either.
		_, err = planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).NotTo(HaveOccurred())
	})

	It("still refuses a real downgrade of this host's build when another platform keeps a higher version", func() {
		r := newSignedRepo(GinkgoTB(), "repo")
		stateHome := GinkgoT().TempDir()
		p := profileWithConstraints("repo", r.OutputDir, r.TrustRoot, map[string]string{"hello": ">=1.0.0"})

		r.PublishEntries(repo.BuildOptions{}, map[string][]fixturePkg{"hello": {
			{Version: "1.5.0", Platform: platform.Host()},
			{Version: "2.0.0", Platform: foreignPlatform()},
		}})
		_, err := planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).NotTo(HaveOccurred())

		// This host's 1.5.0 is withdrawn for 1.0.0; the foreign 2.0.0 stays.
		r.PublishEntries(repo.BuildOptions{}, map[string][]fixturePkg{"hello": {
			{Version: "1.0.0", Platform: platform.Host()},
			{Version: "2.0.0", Platform: foreignPlatform()},
		}})
		_, err = planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).To(MatchError(ContainSubstring("refusing to downgrade hello to 1.0.0: this source previously offered 1.5.0")))
	})

	It("checks the posture floor against this host's entry, not a newer foreign one", func() {
		r := newSignedRepo(GinkgoTB(), "repo")
		stateHome := GinkgoT().TempDir()
		p := profileWithConstraints("repo", r.OutputDir, r.TrustRoot, map[string]string{"hello": ">=1.0.0"})
		host := fixturePkg{Version: "1.0.0", Platform: platform.Host()}

		r.PublishEntries(repo.BuildOptions{}, map[string][]fixturePkg{"hello": {host}})
		res1, err := planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).NotTo(HaveOccurred())
		Expect(res1.Manifest.Entries[0].Attestation.PredicateTypes).To(ContainElement(attest.PredicateTypeSARIF))

		// The publisher adds 2.0.0 for another platform only. The floor's
		// prior entry is hello 1.0.0; the entry it is compared against must be
		// this host's 1.0.0 again, not the foreign 2.0.0.
		r.PublishEntries(repo.BuildOptions{}, map[string][]fixturePkg{"hello": {
			host,
			{Version: "2.0.0", Platform: foreignPlatform()},
		}})
		opts := planOpts(stateHome)
		opts.PriorManifest = res1.Manifest
		res2, err := planner.Plan(GinkgoT().Context(), p, opts)
		Expect(err).NotTo(HaveOccurred())
		Expect(res2.Manifest.Entries[0].Version).To(Equal("1.0.0"))
		Expect(res2.Manifest.Entries[0].Attestation.PredicateTypes).To(ContainElement(attest.PredicateTypeSARIF))
	})

	It("fails naming the published platforms and this host when the package has no entry for this host", func() {
		r := newSignedRepo(GinkgoTB(), "repo")
		r.PublishEntries(repo.BuildOptions{}, map[string][]fixturePkg{"hello": {
			{Version: "1.0.0", Platform: foreignPlatform()},
		}})
		p := profileWithConstraints("repo", r.OutputDir, r.TrustRoot, map[string]string{"hello": ">=1.0.0"})

		_, err := planner.Plan(GinkgoT().Context(), p, planOpts(GinkgoT().TempDir()))
		var re *resolver.ResolveError
		Expect(errors.As(err, &re)).To(BeTrue(), "got %v", err)
		Expect(re.Kind).To(Equal(resolver.KindWrongPlatform))
		Expect(err).To(MatchError(ContainSubstring("hello 1.0.0 is published for %s; this host is %s", foreignPlatform(), platform.Host())))
	})
})

var _ = Describe("Plan with a state home shared across host platforms", func() {
	planOpts := func(stateHome string) planner.Options {
		return planner.Options{Scope: "user", DataHome: GinkgoT().TempDir(), StateHome: stateHome}
	}

	It("does not let another platform's mark refuse this host's older build, and keeps that mark", func() {
		r := newSignedRepo(GinkgoTB(), "repo")
		stateHome := GinkgoT().TempDir()
		Expect(trust.StoreSeen(stateHome, "repo", trust.Seen{PackagesByPlatform: map[string]map[string]string{
			foreignPlatform(): {"hello": "2.0.0"},
		}})).To(Succeed())
		r.PublishEntries(repo.BuildOptions{}, map[string][]fixturePkg{"hello": {{Version: "1.0.0", Platform: platform.Host()}}})
		p := profileWithConstraints("repo", r.OutputDir, r.TrustRoot, map[string]string{"hello": ">=1.0.0"})

		res, err := planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Manifest.Entries[0].Version).To(Equal("1.0.0"))

		seen, err := trust.LoadSeen(stateHome, "repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(seen.PackagesByPlatform).To(Equal(map[string]map[string]string{
			foreignPlatform(): {"hello": "2.0.0"},
			platform.Host():   {"hello": "1.0.0"},
		}))
	})

	It("still refuses a downgrade below this host's own mark", func() {
		r := newSignedRepo(GinkgoTB(), "repo")
		stateHome := GinkgoT().TempDir()
		Expect(trust.StoreSeen(stateHome, "repo", trust.Seen{PackagesByPlatform: map[string]map[string]string{
			foreignPlatform(): {"hello": "0.5.0"},
		}})).To(Succeed())
		p := profileWithConstraints("repo", r.OutputDir, r.TrustRoot, map[string]string{"hello": ">=1.0.0"})

		r.PublishEntries(repo.BuildOptions{}, map[string][]fixturePkg{"hello": {{Version: "1.5.0", Platform: platform.Host()}}})
		_, err := planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).NotTo(HaveOccurred())

		r.PublishEntries(repo.BuildOptions{}, map[string][]fixturePkg{"hello": {{Version: "1.0.0", Platform: platform.Host()}}})
		_, err = planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).To(MatchError(ContainSubstring("refusing to downgrade hello to 1.0.0: this source previously offered 1.5.0")))
	})

	It("adopts a legacy un-keyed mark for this host and rewrites it in the per-platform form", func() {
		r := newSignedRepo(GinkgoTB(), "repo")
		stateHome := GinkgoT().TempDir()
		Expect(trust.StoreSeen(stateHome, "repo", trust.Seen{Packages: map[string]string{"hello": "2.0.0"}})).To(Succeed())
		p := profileWithConstraints("repo", r.OutputDir, r.TrustRoot, map[string]string{"hello": ">=1.0.0"})

		r.Publish(repo.BuildOptions{}, map[string]fixturePkg{"hello": {Version: "1.0.0"}})
		_, err := planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).To(MatchError(ContainSubstring("refusing to downgrade hello to 1.0.0: this source previously offered 2.0.0")))

		r.Publish(repo.BuildOptions{}, map[string]fixturePkg{"hello": {Version: "2.1.0"}})
		_, err = planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).NotTo(HaveOccurred())
		seen, err := trust.LoadSeen(stateHome, "repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(seen.Packages).To(BeEmpty())
		Expect(seen.PackagesByPlatform).To(Equal(map[string]map[string]string{platform.Host(): {"hello": "2.1.0"}}))
	})
})
