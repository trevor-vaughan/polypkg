package integration

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// e2e_lifecycle_test.go walks a fresh user journey against one evolving remote
// repo: init -> search -> info -> plan -> install -> list -> upgrade -> remove
// -> rollback -> status. install/upgrade/remove each auto-apply a generation,
// so generations advance: install hello (1), install world (2), upgrade (3),
// remove world (4), rollback -> 3.
var _ = Describe("fresh UX lifecycle journey", Ordered, func() {
	var (
		anchor, signer     minisignKeypair
		repoDir            string
		srvURL             string
		trustRoot          string
		profile            string
		hello100, world100 []byte
	)

	// manifestPackages returns the installed package names recorded in the
	// manifest of generation gen.
	manifestPackages := func(gen string) []string {
		f, err := os.Open(filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "generations", gen, "manifest.json"))
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = f.Close() }()
		m, err := schema.ParseManifest(f)
		Expect(err).NotTo(HaveOccurred())
		names := make([]string, 0, len(m.Entries))
		for _, p := range m.Entries {
			names = append(names, p.Name)
		}
		return names
	}

	BeforeAll(func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		anchor = newMinisignKeypair(t)
		signer = newMinisignKeypair(t)
		repoDir = t.TempDir()

		hello100 = buildHelloPackage(t)
		world100 = buildPkg(t, "world", "1.0.0", "#!/bin/sh\necho world 1.0.0\n")

		publishTrustDoc(t, repoDir, "native", anchor, 1,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
		publishIndex(t, repoDir, signer, 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: hello100},
			indexPkg{name: "world", version: "1.0.0", artifact: world100},
		)
		writeArtifact(t, repoDir, signer, "hello", "1.0.0", "", "", hello100)
		writeArtifact(t, repoDir, signer, "world", "1.0.0", "", "", world100)
		trustRoot = writeTrustRoot(t, anchor)

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)
		srvURL = srv.URL

		profile = filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "polypkg", "profile.yaml")
		GinkgoT().Setenv("POLYPKG_PROFILE", profile)
	})

	It("step 1: init writes a profile carrying the remote source", func() {
		out, err := runCmd("init", "--source-url", srvURL, "--trust-root-file", trustRoot)
		Expect(err).NotTo(HaveOccurred(), "init: %s", out)
		Expect(out).To(ContainSubstring("wrote "))
		raw, rerr := os.ReadFile(profile)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring(srvURL), "profile must carry the test source URL")
	})

	It("step 2: search finds hello and world in the remote catalog", func() {
		out, err := runCmd("search", "hello")
		Expect(err).NotTo(HaveOccurred(), "search hello: %s", out)
		Expect(out).To(ContainSubstring("hello"))
		out, err = runCmd("search", "world")
		Expect(err).NotTo(HaveOccurred(), "search world: %s", out)
		Expect(out).To(ContainSubstring("world"))
	})

	It("step 3: info reports hello available but not installed", func() {
		out, err := runCmd("info", "hello")
		Expect(err).NotTo(HaveOccurred(), "info hello: %s", out)
		Expect(out).To(ContainSubstring("installed: none"))
		Expect(out).To(ContainSubstring("1.0.0"))
	})

	It("step 4: plan reports nothing pending on the fresh, package-less profile", func() {
		out, err := runCmd("plan")
		Expect(err).NotTo(HaveOccurred(), "plan: %s", out)
		Expect(out).To(ContainSubstring("no changes pending"))
	})

	It("step 5: install hello@=1.0.0 applies generation 1", func() {
		out, err := runCmd("install", "hello@=1.0.0")
		Expect(err).NotTo(HaveOccurred(), "install hello: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))
		raw, rerr := os.ReadFile(profile)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring(`"=1.0.0"`))
		Expect(manifestPackages("1")).To(ContainElement("hello"))
	})

	It("step 6: install world applies generation 2 with both packages", func() {
		out, err := runCmd("install", "world")
		Expect(err).NotTo(HaveOccurred(), "install world: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))
		Expect(manifestPackages("2")).To(ContainElements("hello", "world"))
	})

	It("step 7: list shows hello and world installed", func() {
		out, err := runCmd("list")
		Expect(err).NotTo(HaveOccurred(), "list: %s", out)
		Expect(out).To(ContainSubstring("hello"))
		Expect(out).To(ContainSubstring("world"))
	})

	It("step 8: info now reports hello installed at 1.0.0", func() {
		out, err := runCmd("info", "hello")
		Expect(err).NotTo(HaveOccurred(), "info hello: %s", out)
		Expect(out).To(ContainSubstring("installed: 1.0.0"))
	})

	It("step 9: upgrade hello bumps to 1.1.0 after the remote publishes a newer index", func() {
		// t is It-scoped, used only for the publish helpers' failure reporting;
		// the writes themselves target repoDir, which is owned by BeforeAll and
		// persists across the ordered container.
		t := GinkgoTB()
		hello110 := buildHelloPackageV110()
		// Advance the remote to serial 2 (same anchor + signer) with hello 1.1.0.
		publishTrustDoc(t, repoDir, "native", anchor, 2,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
		publishIndex(t, repoDir, signer, 2,
			indexPkg{name: "hello", version: "1.1.0", artifact: hello110},
			indexPkg{name: "hello", version: "1.0.0", artifact: hello100},
			indexPkg{name: "world", version: "1.0.0", artifact: world100},
		)
		writeArtifact(t, repoDir, signer, "hello", "1.1.0", "", "", hello110)

		out, err := runCmd("upgrade", "hello")
		Expect(err).NotTo(HaveOccurred(), "upgrade hello: %s", out)
		Expect(out).To(ContainSubstring("bumping hello pin"))
		Expect(out).To(ContainSubstring("applied generation"))
		raw, rerr := os.ReadFile(profile)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring(`"=1.1.0"`))
		Expect(string(raw)).NotTo(ContainSubstring(`"=1.0.0"`))
		Expect(manifestPackages("3")).To(ContainElements("hello", "world"))
	})

	It("step 10: remove world tears it down, leaving hello", func() {
		out, err := runCmd("remove", "world")
		Expect(err).NotTo(HaveOccurred(), "remove world: %s", out)
		Expect(out).To(ContainSubstring("removing world"))
		Expect(out).To(ContainSubstring("applied generation"))
		raw, rerr := os.ReadFile(profile)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(raw)).NotTo(ContainSubstring("world:"))
		Expect(manifestPackages("4")).To(ContainElement("hello"))
		Expect(manifestPackages("4")).NotTo(ContainElement("world"))
	})

	It("step 11: rollback restores world alongside hello 1.1.0", func() {
		out, err := runCmd("rollback")
		Expect(err).NotTo(HaveOccurred(), "rollback: %s", out)
		Expect(out).To(ContainSubstring("rolled back to generation 3"))
		Expect(manifestPackages("3")).To(ContainElements("hello", "world"))

		// list reads the active generation: world (removed in step 10) must be
		// back, proving rollback re-activated generation 3, not just that gen 3's
		// on-disk manifest is unchanged.
		listOut, listErr := runCmd("list")
		Expect(listErr).NotTo(HaveOccurred(), "list after rollback: %s", listOut)
		Expect(listOut).To(ContainSubstring("hello"))
		Expect(listOut).To(ContainSubstring("world"))
	})

	It("step 12: status reports the current generation after rollback", func() {
		out, err := runCmd("status")
		Expect(err).NotTo(HaveOccurred(), "status: %s", out)
		Expect(out).To(MatchRegexp(`current generation: 3`))
	})
})
