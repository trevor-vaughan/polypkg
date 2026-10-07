package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// twoSourceProfile pins nothing; order=[a,b].
func twoSourceProfile(urlA, trustA, urlB, trustB string) string {
	return fmt.Sprintf(`schema: polypkg.spec/v1
name: multisource-test
scopes:
  user:
    substrate: store
    prefix: $XDG_DATA_HOME/polypkg
sources:
  order: [a, b]
  a:
    type: polypkg-native
    url: %s
    trust_root: %s
  b:
    type: polypkg-native
    url: %s
    trust_root: %s
`, urlA, trustA, urlB, trustB)
}

var _ = Describe("multi-source", func() {
	It("resolves a package only present in the lower-priority source from that source", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		pkgHello := buildHelloPackage(t)
		repoA := t.TempDir()
		trustA := signRepo(t, repoA, "a", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkgHello})
		srvA := httptest.NewServer(http.FileServer(http.Dir(repoA)))
		DeferCleanup(srvA.Close)

		pkgWorld := buildPkg(t, "world", "2.0.0", "#!/bin/sh\necho world\n")
		repoB := t.TempDir()
		trustB := signRepo(t, repoB, "b", 1, indexPkg{name: "world", version: "2.0.0", artifact: pkgWorld})
		srvB := httptest.NewServer(http.FileServer(http.Dir(repoB)))
		DeferCleanup(srvB.Close)

		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		body := twoSourceProfile(srvA.URL, trustA, srvB.URL, trustB) +
			"packages:\n  user:\n    world:\n      version: \">=2.0.0\"\n"
		Expect(os.WriteFile(profilePath, []byte(body), 0o644)).To(Succeed())

		out, err := runCmd("apply", profilePath)
		Expect(err).NotTo(HaveOccurred(), "apply failed: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))
	})

	It("fails fast when a configured source is unreachable", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		pkgHello := buildHelloPackage(t)
		repoA := t.TempDir()
		trustA := signRepo(t, repoA, "a", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkgHello})
		srvA := httptest.NewServer(http.FileServer(http.Dir(repoA)))
		DeferCleanup(srvA.Close)

		// Source B points at a dead address; even though our package is in A,
		// B is in order and unreachable -> fail-fast.
		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		body := twoSourceProfile(srvA.URL, trustA, "http://127.0.0.1:1", trustA) +
			"packages:\n  user:\n    hello:\n      version: \"=1.0.0\"\n"
		Expect(os.WriteFile(profilePath, []byte(body), 0o644)).To(Succeed())

		out, err := runCmd("apply", profilePath)
		Expect(err).To(HaveOccurred(), "apply must fail fast on an unreachable source; out: %s", out)
		dataHome := os.Getenv("XDG_DATA_HOME")
		_, statErr := os.Lstat(filepath.Join(dataHome, "polypkg", "active"))
		Expect(statErr).To(HaveOccurred(), "no generation may be activated when a source is unreachable")
	})

	It("verifies a pinned package against its own source's keyring", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		// Both A and B publish hello (each signed by its own independent key).
		// A pin forces hello from B; it must fetch from B and verify under B's keyring.
		pkgHello := buildHelloPackage(t)
		repoA := t.TempDir()
		trustA := signRepo(t, repoA, "a", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkgHello})
		srvA := httptest.NewServer(http.FileServer(http.Dir(repoA)))
		DeferCleanup(srvA.Close)
		repoB := t.TempDir()
		trustB := signRepo(t, repoB, "b", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkgHello})
		srvB := httptest.NewServer(http.FileServer(http.Dir(repoB)))
		DeferCleanup(srvB.Close)

		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		body := twoSourceProfile(srvA.URL, trustA, srvB.URL, trustB) +
			"packages:\n  user:\n    hello:\n      version: \"=1.0.0\"\n      source: b\n"
		Expect(os.WriteFile(profilePath, []byte(body), 0o644)).To(Succeed())

		out, err := runCmd("apply", profilePath)
		Expect(err).NotTo(HaveOccurred(), "pinned-source apply failed: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))
	})

	It("rejects a pinned source's artifact signed by a key outside that source's trust set", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		pkgHello := buildHelloPackage(t)

		// Source A: a normal, valid, reachable source (publishes some other pkg).
		pkgWorld := buildPkg(t, "world", "1.0.0", "#!/bin/sh\necho world\n")
		repoA := t.TempDir()
		trustA := signRepo(t, repoA, "a", 1, indexPkg{name: "world", version: "1.0.0", artifact: pkgWorld})
		srvA := httptest.NewServer(http.FileServer(http.Dir(repoA)))
		DeferCleanup(srvA.Close)

		// Source B: properly-signed trust doc + index naming hello, but the hello
		// ARTIFACT is signed by an UNTRUSTED key (not listed in B's trust doc).
		repoB := t.TempDir()
		anchorB := newMinisignKeypair(t)
		signerB := newMinisignKeypair(t)   // trusted: signs B's trust doc + index
		untrusted := newMinisignKeypair(t) // NOT in B's trust set; signs the artifact
		publishTrustDoc(t, repoB, "b", anchorB, 1,
			[]trustKeySpec{{kp: signerB, roles: []string{"index", "artifact"}}}, nil)
		publishIndex(t, repoB, signerB, 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkgHello})
		writeArtifact(t, repoB, untrusted, "hello", "1.0.0", "", "", pkgHello) // bad signature
		trustB := writeTrustRoot(t, anchorB)
		srvB := httptest.NewServer(http.FileServer(http.Dir(repoB)))
		DeferCleanup(srvB.Close)

		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		body := twoSourceProfile(srvA.URL, trustA, srvB.URL, trustB) +
			"packages:\n  user:\n    hello:\n      version: \"=1.0.0\"\n      source: b\n"
		Expect(os.WriteFile(profilePath, []byte(body), 0o644)).To(Succeed())

		out, err := runCmd("apply", profilePath)
		Expect(err).To(HaveOccurred(), "apply must reject B's artifact signed by an untrusted key; out: %s", out)
		// runCmd silences cobra's error output, so the rejection reason rides on
		// err, not the captured progress stream. Lock in the specific guarantee:
		// the failure is the untrusted-key rejection, not an unrelated error.
		Expect(err.Error()).To(ContainSubstring("is not in the trust set"),
			"failure must be the untrusted-key rejection, not an unrelated error; err: %v; out: %s", err, out)
		dataHome := os.Getenv("XDG_DATA_HOME")
		_, statErr := os.Lstat(filepath.Join(dataHome, "polypkg", "active"))
		Expect(statErr).To(HaveOccurred(), "no generation may be activated when artifact verification fails")
	})

	It("installs the higher-priority source's version when both sources have the package, and that binary runs", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		// Both sources publish `hello`, but with different versions AND different
		// script content, so we can prove WHICH source's artifact was placed.
		// order=[a,b]; A is higher priority, so A wins even though B has a newer version.
		helloA := buildPkg(t, "hello", "1.0.0", "#!/bin/sh\necho hello from source A\n")
		helloB := buildPkg(t, "hello", "1.1.0", "#!/bin/sh\necho hello from source B\n")

		repoA := t.TempDir()
		trustA := signRepo(t, repoA, "a", 1, indexPkg{name: "hello", version: "1.0.0", artifact: helloA})
		srvA := httptest.NewServer(http.FileServer(http.Dir(repoA)))
		DeferCleanup(srvA.Close)

		repoB := t.TempDir()
		trustB := signRepo(t, repoB, "b", 1, indexPkg{name: "hello", version: "1.1.0", artifact: helloB})
		srvB := httptest.NewServer(http.FileServer(http.Dir(repoB)))
		DeferCleanup(srvB.Close)

		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		body := twoSourceProfile(srvA.URL, trustA, srvB.URL, trustB) +
			"packages:\n  user:\n    hello:\n      version: \">=1.0.0\"\n"
		Expect(os.WriteFile(profilePath, []byte(body), 0o644)).To(Succeed())

		out, err := runCmd("apply", profilePath)
		Expect(err).NotTo(HaveOccurred(), "apply failed: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))

		// Overlay: A owns "hello" (first in order with the name), so A's 1.0.0 is
		// installed even though B has 1.1.0. Verify via the placed binary's output.
		dataHome := os.Getenv("XDG_DATA_HOME")
		helloBin := filepath.Join(dataHome, "polypkg", "active", "hello", "bin", "hello")
		runOut, runErr := exec.Command("sh", helloBin).CombinedOutput()
		Expect(runErr).NotTo(HaveOccurred(), "installed hello binary failed to run: %s", string(runOut))
		Expect(string(runOut)).To(ContainSubstring("hello from source A"),
			"overlay must install source A's artifact (1.0.0), not B's (1.1.0); got: %s", string(runOut))
	})
})
