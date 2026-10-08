package integration

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/extractstore"
)

// Guards the extract-store integrity fix: before content-addressed extract
// dirs, a same-version republish RemoveAll'd pkg-extract/<name>-<version> —
// the very tree every retained generation's symlinks resolve through — so
// history silently changed under pinned generations and rollback executed
// bytes the generation's manifest never verified.
//
// The journey publishes widget 1.0.0 (content-A), installs and pins it, then
// republishes the SAME name-version with different bytes (content-B) and
// reinstalls. Every assertion reads real bytes through the real generation
// symlinks — exactly the path rollback executes — not just dir existence.
var _ = Describe("same-version republish integrity", Ordered, func() {
	var (
		contentADir, contentBDir string
		dataHome, extractRoot    string
	)

	// placedFile is the file the install action places for widget in generation
	// gen: a symlink whose target resolves through the extract store. Reading
	// it with os.ReadFile follows the symlink, so the returned bytes are what
	// that generation would actually execute.
	placedFile := func(gen string) string {
		return filepath.Join(dataHome, "polypkg", "generations", gen, "active", "widget", "bin", "widget")
	}

	BeforeAll(func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		dataHome = os.Getenv("XDG_DATA_HOME")
		extractRoot = filepath.Join(os.Getenv("XDG_STATE_HOME"), "polypkg", "pkg-extract")

		anchor := newMinisignKeypair(t)
		signer := newMinisignKeypair(t)
		repoDir := t.TempDir()

		// Same name, same version, different placed-file bytes: the exact
		// same-version-republish shape that exposed the bug.
		artifactA := buildPkg(t, "widget", "1.0.0", "content-A")
		artifactB := buildPkg(t, "widget", "1.0.0", "content-B")
		contentADir = extractstore.DirName("widget", "1.0.0", blakeHash(artifactA))
		contentBDir = extractstore.DirName("widget", "1.0.0", blakeHash(artifactB))

		publishTrustDoc(t, repoDir, "native", anchor, 1,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
		publishIndex(t, repoDir, signer, 1,
			indexPkg{name: "widget", version: "1.0.0", artifact: artifactA})
		writeArtifact(t, repoDir, signer, "widget", "1.0.0", "", "", artifactA)
		trustRoot := writeTrustRoot(t, anchor)

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)

		profile := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "polypkg", "profile.yaml")
		GinkgoT().Setenv("POLYPKG_PROFILE", profile)
		out, err := runCmd("init", "--source-url", srv.URL, "--trust-root", trustRoot)
		Expect(err).NotTo(HaveOccurred(), "init: %s", out)

		// The whole journey up to the republish lives here, not in specs, so
		// every spec below runs on its own (ginkgo --focus) as well as in
		// sequence: each one needs generations 1 (content A, pinned) and 3
		// (content B) to exist.
		out, err = runCmd("install", "widget@=1.0.0") // generation 1
		Expect(err).NotTo(HaveOccurred(), "install widget: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))

		out, err = runCmd("generation", "pin", "1", "--reason", "republish-integrity baseline")
		Expect(err).NotTo(HaveOccurred(), "pin 1: %s", out)

		body, rerr := os.ReadFile(placedFile("1"))
		Expect(rerr).NotTo(HaveOccurred(), "read gen 1 placed file")
		Expect(string(body)).To(Equal("content-A"), "baseline: generation 1 places content A")

		// Republish at serial 2 with the SAME anchor+signer (fresh keys would
		// break the trust chain). Artifact B gets a distinct published path —
		// mirroring the real publisher's content-addressed pool — so the
		// client's name-keyed artifact cache cannot serve stale content-A bytes.
		poolB := "pool/" + contentBDir + ".tar.zst"
		publishTrustDoc(t, repoDir, "native", anchor, 2,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
		publishIndex(t, repoDir, signer, 2,
			indexPkg{name: "widget", version: "1.0.0", artifact: artifactB, artifactName: poolB})
		writeArtifact(t, repoDir, signer, "widget", "1.0.0", "", poolB, artifactB)

		out, err = runCmd("remove", "widget") // generation 2
		Expect(err).NotTo(HaveOccurred(), "remove widget: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))

		out, err = runCmd("install", "widget@=1.0.0") // generation 3
		Expect(err).NotTo(HaveOccurred(), "reinstall widget: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))
	})

	It("keeps generation 1's bytes intact (the regression)", func() {
		// Regression sanity: this spec FAILS against the pre-fix planner
		// (legacy name-version extract dir + unconditional RemoveAll+extract
		// in ensureExtracted), verified during development — the reinstall
		// above rewrote the tree gen 1's symlinks resolve through, so this
		// read returned "content-B".
		body, err := os.ReadFile(placedFile("1"))
		Expect(err).NotTo(HaveOccurred(), "gen 1 placed file must still resolve after the republish")
		Expect(string(body)).To(Equal("content-A"),
			"a same-version republish must never rewrite the bytes a retained generation resolves to")
	})

	It("serves content B in the new generation", func() {
		body, err := os.ReadFile(placedFile("3"))
		Expect(err).NotTo(HaveOccurred(), "read gen 3 placed file")
		Expect(string(body)).To(Equal("content-B"))
	})

	It("rollback to the pinned generation executes content A", func() {
		out, err := runCmd("rollback", "--to", "1")
		Expect(err).NotTo(HaveOccurred(), "rollback --to 1: %s", out)

		// Read THROUGH the repointed active symlink — the exact path a user's
		// shell resolves after rollback.
		body, rerr := os.ReadFile(filepath.Join(dataHome, "polypkg", "active", "widget", "bin", "widget"))
		Expect(rerr).NotTo(HaveOccurred(), "read placed file via active symlink after rollback")
		Expect(string(body)).To(Equal("content-A"),
			"rollback must execute the bytes generation 1's manifest verified")
	})

	It("gc sweeps only unreferenced extract dirs", func() {
		t := GinkgoTB()
		out, err := runCmd("rollback", "--to", "3") // roll forward: gen 3 is current again
		Expect(err).NotTo(HaveOccurred(), "rollback --to 3: %s", out)
		out, err = runCmd("generation", "unpin", "1")
		Expect(err).NotTo(HaveOccurred(), "unpin 1: %s", out)

		// Pre-sweep sanity: both content-addressed dirs exist, confirming the
		// DirName-derived names match what the planner actually extracted.
		Expect(filepath.Join(extractRoot, contentADir)).To(BeADirectory(),
			"content-A extract dir must exist before the sweep")
		Expect(filepath.Join(extractRoot, contentBDir)).To(BeADirectory(),
			"content-B extract dir must exist before the sweep")

		// Age every extract dir past the sweep's grace window
		// (extractstore.DefaultMinAge) — otherwise it would keep everything.
		ageExtractDirs(t, extractRoot)

		// count=1 retains only current gen 3; gens 1 and 2 are evicted, so
		// only gen 3's manifest feeds the sweep's keep set.
		out, err = runCmd("gc", "--count", "1", "--age", "0s")
		Expect(err).NotTo(HaveOccurred(), "gc: %s", out)
		Expect(out).To(ContainSubstring("swept"), "gc must report the extract-dir sweep: %s", out)

		var widgetDirs []string
		for _, name := range extractDirNames(t, extractRoot) {
			if strings.HasPrefix(name, "widget-1.0.0+") {
				widgetDirs = append(widgetDirs, name)
			}
		}
		Expect(widgetDirs).To(ConsistOf(contentBDir),
			"exactly the content-B extract dir (referenced by gen 3) must survive the sweep")
		Expect(contentBDir).NotTo(Equal(contentADir),
			"fixture sanity: the two artifacts must land in distinct content-addressed dirs")
	})
})
