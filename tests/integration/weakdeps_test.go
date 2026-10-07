package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/cli"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// weakProfile builds a minimal profile YAML selecting pkgName (any version)
// from the given source, with an optional recommends block appended.
func weakProfile(srvURL, trustRoot, pkgName string, extraYAML string) string {
	base := "schema: polypkg.spec/v1\n" +
		"name: weak-test\n" +
		"scopes:\n  user:\n    substrate: store\n    prefix: $XDG_DATA_HOME/polypkg\n" +
		"sources:\n  order: [native]\n  native:\n    type: polypkg-native\n" +
		"    url: " + srvURL + "\n    trust_root: " + trustRoot + "\n" +
		"packages:\n  user:\n    " + pkgName + ":\n      version: \"*\"\n"
	if extraYAML != "" {
		base += extraYAML
	}
	return base
}

// readManifest opens and parses the manifest for generation gen.
func readManifest(gen string) *schema.Manifest {
	GinkgoHelper()
	f, err := os.Open(filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "generations", gen, "manifest.json"))
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = f.Close() }()
	m, err := schema.ParseManifest(f)
	Expect(err).NotTo(HaveOccurred())
	return m
}

// runApplyProfile runs `polypkg apply <profilePath>` in-process and returns
// combined output and the error.
func runApplyProfile(profilePath string) (string, error) {
	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"apply", profilePath})
	err := cmd.Execute()
	return buf.String(), err
}

// minimalPkg builds a tar.zst containing only a polypkg.yaml with no actions —
// enough for the resolver/planner to place and track the package.
func minimalPkg(name, version string) []byte {
	return buildTarZst(GinkgoTB(), map[string]string{
		"polypkg.yaml": "schema: polypkg.package/v1\nname: " + name + "\nversion: " + version + "\nactions: []\n",
	})
}

var _ = Describe("forward weak dependencies", func() {
	// Scenario 1 + 2 share a repo server; each step builds on the prior state.
	Describe("pulled in and fall out by construction", Ordered, func() {
		var (
			repoDir   string
			anchor    minisignKeypair
			signer    minisignKeypair
			srvURL    string
			trustRoot string
			srv       *httptest.Server
		)

		BeforeAll(func() {
			t := GinkgoTB()
			IsolatedEnv(t)

			anchor = newMinisignKeypair(t)
			signer = newMinisignKeypair(t)
			repoDir = t.TempDir()

			appPkg := minimalPkg("app", "1.0.0")
			extrasPkg := minimalPkg("extras", "1.0.0")

			// Publish serial 1: app recommends extras, extras exists.
			publishTrustDoc(t, repoDir, "native", anchor, 1,
				[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
			publishIndex(t, repoDir, signer, 1,
				indexPkg{
					name:     "app",
					version:  "1.0.0",
					artifact: appPkg,
					recommends: []schema.Relation{
						{Name: "extras"},
					},
				},
				indexPkg{name: "extras", version: "1.0.0", artifact: extrasPkg},
			)
			writeArtifact(t, repoDir, signer, "app", "1.0.0", "", "", appPkg)
			writeArtifact(t, repoDir, signer, "extras", "1.0.0", "", "", extrasPkg)

			trustRoot = writeTrustRoot(t, anchor)
			srv = httptest.NewServer(http.FileServer(http.Dir(repoDir)))
			DeferCleanup(srv.Close)
			srvURL = srv.URL
		})

		It("step 1: app pulls in extras as a weak dep", func() {
			profile := weakProfile(srvURL, trustRoot, "app", "")
			profilePath := filepath.Join(GinkgoT().TempDir(), "profile.yaml")
			Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())

			out, err := runApplyProfile(profilePath)
			Expect(err).NotTo(HaveOccurred(), "apply err (output: %q)", out)
			Expect(out).To(ContainSubstring("applied generation 1"), "apply output was: %q", out)

			m := readManifest("1")

			var appEntry, extrasEntry *schema.ManifestEntry
			for i := range m.Entries {
				switch m.Entries[i].Name {
				case "app":
					appEntry = &m.Entries[i]
				case "extras":
					extrasEntry = &m.Entries[i]
				}
			}

			Expect(appEntry).NotTo(BeNil(), "app must be in the manifest")
			Expect(extrasEntry).NotTo(BeNil(), "extras must be pulled in as a weak dep")

			Expect(appEntry.Weak).To(BeFalse(), "app is a direct package, not weak")
			Expect(extrasEntry.Weak).To(BeTrue(), "extras must be marked weak")
			Expect(extrasEntry.RecommendedBy).To(ContainElement("app"),
				"extras.RecommendedBy must include app")
		})

		It("step 2: dropping app from the profile makes extras fall out (declarative autoremove)", func() {
			// Publish a neutral package 'base' so we have something to select
			// without recommending extras. Bump to serial 2 (same anchor+signer) to
			// avoid a rollback rejection.
			t := GinkgoTB()
			basePkg := minimalPkg("base", "1.0.0")
			appPkg := minimalPkg("app", "1.0.0")
			extrasPkg := minimalPkg("extras", "1.0.0")

			publishTrustDoc(t, repoDir, "native", anchor, 2,
				[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
			publishIndex(t, repoDir, signer, 2,
				indexPkg{
					name:     "app",
					version:  "1.0.0",
					artifact: appPkg,
					recommends: []schema.Relation{
						{Name: "extras"},
					},
				},
				indexPkg{name: "extras", version: "1.0.0", artifact: extrasPkg},
				indexPkg{name: "base", version: "1.0.0", artifact: basePkg},
			)
			writeArtifact(t, repoDir, signer, "base", "1.0.0", "", "", basePkg)

			// Profile now selects 'base' only — extras has no recommender.
			profile := weakProfile(srvURL, trustRoot, "base", "")
			profilePath := filepath.Join(t.TempDir(), "profile.yaml")
			Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())

			out, err := runApplyProfile(profilePath)
			Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)
			Expect(out).To(ContainSubstring("applied generation 2"))

			m := readManifest("2")
			names := make([]string, 0, len(m.Entries))
			for _, e := range m.Entries {
				names = append(names, e.Name)
			}
			Expect(names).To(ContainElement("base"), "base must be installed")
			Expect(names).NotTo(ContainElement("extras"),
				"extras must fall out when no package recommends it")
			Expect(names).NotTo(ContainElement("app"),
				"app was removed from the profile")
		})
	})

	// Describe: weak set tracks the catalog (Q5)
	//
	// Decision Q5 states that the weak set is re-evaluated on every resolve
	// against the current signed catalog, not pinned at first-apply time.
	//
	// Proof: a recommend that is UNSATISFIABLE at serial 1 (its target absent
	// from the catalog) is skipped and NOT installed; after a catalog republish
	// at serial 2 that ADDS the target, the SAME profile re-applied pulls the
	// target in as a weak dep — no profile change required.
	Describe("weak set tracks the catalog (Q5)", Ordered, func() {
		var (
			repoDir   string
			anchor    minisignKeypair
			signer    minisignKeypair
			srvURL    string
			trustRoot string
			srv       *httptest.Server
			// profilePath is shared across both steps so we confirm it is unchanged.
			profilePath string
		)

		BeforeAll(func() {
			t := GinkgoTB()
			IsolatedEnv(t)

			anchor = newMinisignKeypair(t)
			signer = newMinisignKeypair(t)
			repoDir = t.TempDir()

			// Serial 1: publish only 'app' (recommends extras); 'extras' is absent
			// from the index so the weak solve cannot satisfy the recommend.
			appPkg := minimalPkg("app", "1.0.0")
			publishTrustDoc(t, repoDir, "native", anchor, 1,
				[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
			publishIndex(t, repoDir, signer, 1,
				indexPkg{
					name:     "app",
					version:  "1.0.0",
					artifact: appPkg,
					recommends: []schema.Relation{
						{Name: "extras"},
					},
				},
				// NOTE: extras is intentionally absent from the serial-1 index.
			)
			writeArtifact(t, repoDir, signer, "app", "1.0.0", "", "", appPkg)

			trustRoot = writeTrustRoot(t, anchor)
			srv = httptest.NewServer(http.FileServer(http.Dir(repoDir)))
			DeferCleanup(srv.Close)
			srvURL = srv.URL

			// Write the profile once; it must not change between steps.
			profile := weakProfile(srvURL, trustRoot, "app", "")
			profilePath = filepath.Join(t.TempDir(), "profile.yaml")
			Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())
		})

		It("step 1: unsatisfiable recommend is skipped and not installed", func() {
			// Use plan first to assert extras appears in skipped_recommends with the
			// correct recommender attribution, before altering any state.
			out, err := runPlanCmd("--format", "json", profilePath)
			// plan exits non-zero (exit 2) when there are changes pending — that is
			// expected for a first-run plan.  Any non-JSON output line means something
			// truly broke.
			if err != nil {
				Expect(out).NotTo(BeEmpty(), "expected plan output on non-zero exit")
			}
			lines := strings.Split(strings.TrimSpace(out), "\n")
			last := lines[len(lines)-1]
			pr, perr := schema.ParsePlanResult(strings.NewReader(last))
			Expect(perr).NotTo(HaveOccurred(), "parse plan JSON: %s", last)

			Expect(pr.SkippedRecommends).NotTo(BeEmpty(),
				"extras must appear in skipped_recommends when absent from catalog at serial 1")
			var foundSkip bool
			for _, s := range pr.SkippedRecommends {
				if s.Name == "extras" {
					foundSkip = true
					Expect(s.RecommendedBy).To(ContainElement("app"),
						"skipped recommend must name its recommender")
					break
				}
			}
			Expect(foundSkip).To(BeTrue(),
				"extras not found in skipped_recommends: %v", pr.SkippedRecommends)

			// Now apply: must succeed (unmet recommends never abort an install).
			applyOut, applyErr := runApplyProfile(profilePath)
			Expect(applyErr).NotTo(HaveOccurred(), "apply output: %s", applyOut)
			Expect(applyOut).To(ContainSubstring("applied generation 1"), "apply output: %s", applyOut)

			// Manifest gen-1 must contain app but NOT extras.
			m := readManifest("1")
			names := make([]string, 0, len(m.Entries))
			for _, e := range m.Entries {
				names = append(names, e.Name)
			}
			Expect(names).To(ContainElement("app"), "app must be in gen-1 manifest")
			Expect(names).NotTo(ContainElement("extras"),
				"extras must be absent from gen-1 manifest: the unsatisfiable recommend was skipped")
		})

		It("step 2: republish adds extras → same profile pulls it in as a weak dep", func() {
			t := GinkgoTB()

			// Serial 2: republish index with both app and extras now present.
			// Same anchor+signer; bump serial to avoid rollback rejection.
			appPkg := minimalPkg("app", "1.0.0")
			extrasPkg := minimalPkg("extras", "1.0.0")
			publishTrustDoc(t, repoDir, "native", anchor, 2,
				[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
			publishIndex(t, repoDir, signer, 2,
				indexPkg{
					name:     "app",
					version:  "1.0.0",
					artifact: appPkg,
					recommends: []schema.Relation{
						{Name: "extras"},
					},
				},
				indexPkg{name: "extras", version: "1.0.0", artifact: extrasPkg},
			)
			writeArtifact(t, repoDir, signer, "extras", "1.0.0", "", "", extrasPkg)

			// Re-apply the SAME profile — no profile edit.
			applyOut, applyErr := runApplyProfile(profilePath)
			Expect(applyErr).NotTo(HaveOccurred(), "apply output: %s", applyOut)
			Expect(applyOut).To(ContainSubstring("applied generation 2"), "apply output: %s", applyOut)

			// Manifest gen-2 must contain extras, marked as a weak dep of app.
			m := readManifest("2")
			var extrasEntry *schema.ManifestEntry
			for i := range m.Entries {
				if m.Entries[i].Name == "extras" {
					extrasEntry = &m.Entries[i]
					break
				}
			}
			Expect(extrasEntry).NotTo(BeNil(),
				"extras must be in gen-2 manifest after catalog was updated to include it")
			Expect(extrasEntry.Weak).To(BeTrue(),
				"extras must be marked weak (pulled in by recommend, not directly selected)")
			Expect(extrasEntry.RecommendedBy).To(ContainElement("app"),
				"extras.RecommendedBy must include app")
		})
	})

	Describe("skipped on conflict", func() {
		// app2 hard-depends lib =1.0.0 and recommends wants-lib2, which depends
		// lib =2.0.0.  The recommend conflicts with the pinned lib and must be
		// skipped.
		It("reports the conflicting recommend as skipped in plan JSON output", func() {
			t := GinkgoTB()
			IsolatedEnv(t)

			repoDir := t.TempDir()

			lib1Pkg := minimalPkg("lib", "1.0.0")
			lib2Pkg := minimalPkg("lib", "2.0.0")
			wantsLib2Pkg := buildTarZst(t, map[string]string{
				"polypkg.yaml": "schema: polypkg.package/v1\nname: wants-lib2\nversion: 1.0.0\n" +
					"depends:\n  - name: lib\n    version: \"=2.0.0\"\nactions: []\n",
			})
			app2Pkg := buildTarZst(t, map[string]string{
				"polypkg.yaml": "schema: polypkg.package/v1\nname: app2\nversion: 1.0.0\n" +
					"depends:\n  - name: lib\n    version: \"=1.0.0\"\nactions: []\n",
			})

			trustRoot := signRepo(t, repoDir, "native", 1,
				indexPkg{
					name:     "app2",
					version:  "1.0.0",
					artifact: app2Pkg,
					depends:  []schema.Relation{{Name: "lib", Version: "=1.0.0"}},
					recommends: []schema.Relation{
						{Name: "wants-lib2"},
					},
				},
				indexPkg{name: "lib", version: "1.0.0", artifact: lib1Pkg},
				indexPkg{name: "lib", version: "2.0.0", artifact: lib2Pkg},
				indexPkg{
					name:     "wants-lib2",
					version:  "1.0.0",
					artifact: wantsLib2Pkg,
					depends:  []schema.Relation{{Name: "lib", Version: "=2.0.0"}},
				},
			)

			srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
			defer srv.Close()

			profile := weakProfile(srv.URL, trustRoot, "app2", "")
			profilePath := filepath.Join(t.TempDir(), "profile.yaml")
			Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())

			// Use plan (not apply) so we can inspect skipped_recommends without
			// permanently altering state.
			out, err := runPlanCmd("--format", "json", profilePath)
			// plan exits non-zero (exit 2) when there are changes pending; that's
			// expected for a first-run plan.  Any other error is a failure.
			if err != nil {
				// errPlanChangesPending exits 2 — allowed here.
				Expect(out).NotTo(BeEmpty(), "expected plan output on non-zero exit")
			}

			lines := strings.Split(strings.TrimSpace(out), "\n")
			last := lines[len(lines)-1]
			pr, perr := schema.ParsePlanResult(strings.NewReader(last))
			Expect(perr).NotTo(HaveOccurred(), "plan output: %s", last)

			Expect(pr.SkippedRecommends).NotTo(BeEmpty(),
				"wants-lib2 must appear in skipped_recommends (conflicts with lib =1.0.0)")
			found := false
			for _, s := range pr.SkippedRecommends {
				if s.Name == "wants-lib2" {
					found = true
					Expect(s.RecommendedBy).To(ContainElement("app2"),
						"skipped recommend must name its recommender")
					break
				}
			}
			Expect(found).To(BeTrue(), "wants-lib2 not found in skipped_recommends: %v", pr.SkippedRecommends)
		})
	})
})
