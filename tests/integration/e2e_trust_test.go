package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/cli"
)

func helloArtifact(t testing.TB) []byte {
	t.Helper()
	return buildTarZst(t, map[string]string{
		"polypkg.yaml": "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n",
	})
}

// applyHello renders the install-hello profile against url+trustRoot, runs
// apply, and returns combined stdout and the error.
func applyHello(t testing.TB, url, trustRoot string) (string, error) {
	t.Helper()
	g := NewWithT(t)
	profilePath := filepath.Join(t.TempDir(), "profile.yaml")
	g.Expect(os.WriteFile(profilePath, []byte(installHelloProfile(t, url, trustRoot)), 0o644)).To(Succeed())
	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"apply", profilePath})
	err := cmd.Execute()
	return out.String(), err
}

var _ = Describe("trust", func() {
	It("rejects an artifact signed by a revoked key", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		repoDir := t.TempDir()
		art := helloArtifact(t)

		anchor := newMinisignKeypair(t)
		idxKey := newMinisignKeypair(t)
		artKey := newMinisignKeypair(t)
		publishTrustDoc(t, repoDir, "native", anchor, 1,
			[]trustKeySpec{{kp: idxKey, roles: []string{"index"}}}, []string{artKey.keyIDHex()})
		publishIndex(t, repoDir, idxKey, 1, indexPkg{name: "hello", version: "1.0.0", artifact: art})
		writeArtifact(t, repoDir, artKey, "hello", "1.0.0", "", "", art) // signed by the revoked key

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHello(t, srv.URL, writeTrustRoot(t, anchor))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("revoked"))
	})

	It("collapses a tampered-artifact crypto failure to a clean source-named message", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		repoDir := t.TempDir()
		art := helloArtifact(t)

		anchor := newMinisignKeypair(t)
		signer := newMinisignKeypair(t)
		publishTrustDoc(t, repoDir, "native", anchor, 1,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
		publishIndex(t, repoDir, signer, 1, indexPkg{name: "hello", version: "1.0.0", artifact: art})
		writeArtifact(t, repoDir, signer, "hello", "1.0.0", "", "", art)
		// Tamper the artifact bytes on disk AFTER signing so the served bytes no
		// longer match the (valid, trusted) signature: a pure cryptographic
		// mismatch, the Finding D tampered-bytes case.
		tampered := append(append([]byte{}, art...), []byte("TAMPERED")...)
		Expect(os.WriteFile(filepath.Join(repoDir, "hello-1.0.0.tar.zst"), tampered, 0o644)).To(Succeed())

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHello(t, srv.URL, writeTrustRoot(t, anchor))
		Expect(err).To(HaveOccurred())
		// Clean, source-named message; the verifier's failure-mode detail must
		// not leak (SECURITY: it would help an attacker probe the verifier).
		Expect(err.Error()).To(ContainSubstring(`signature verification failed for hello-1.0.0 from source "native"`))
		Expect(err.Error()).NotTo(ContainSubstring("does not match data"))
		Expect(err.Error()).NotTo(ContainSubstring("verify signature"))
	})

	It("rejects role confusion (artifact-only key used to sign the index)", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		repoDir := t.TempDir()
		art := helloArtifact(t)

		anchor := newMinisignKeypair(t)
		artOnly := newMinisignKeypair(t) // artifact role only, used to sign the index
		publishTrustDoc(t, repoDir, "native", anchor, 1,
			[]trustKeySpec{{kp: artOnly, roles: []string{"artifact"}}}, nil)
		publishIndex(t, repoDir, artOnly, 1, indexPkg{name: "hello", version: "1.0.0", artifact: art})
		writeArtifact(t, repoDir, artOnly, "hello", "1.0.0", "", "", art)

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHello(t, srv.URL, writeTrustRoot(t, anchor))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("role"))
	})

	It("rejects a comment-name mismatch", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		repoDir := t.TempDir()
		art := helloArtifact(t)

		anchor := newMinisignKeypair(t)
		signer := newMinisignKeypair(t)
		publishTrustDoc(t, repoDir, "native", anchor, 1,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
		publishIndex(t, repoDir, signer, 1, indexPkg{name: "hello", version: "1.0.0", artifact: art})
		// Artifact signature claims a DIFFERENT name than the resolved entry.
		Expect(os.WriteFile(filepath.Join(repoDir, "hello-1.0.0.tar.zst"), art, 0o644)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(repoDir, "hello-1.0.0.tar.zst.minisig"),
			[]byte(signer.signWithComment(art, "name=evil version=1.0.0 platform=any hash="+blakeHash(art))), 0o644)).To(Succeed())

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHello(t, srv.URL, writeTrustRoot(t, anchor))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("claims"))
	})

	It("rejects an artifact whose signed platform differs from its index entry", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		repoDir := t.TempDir()
		art := helloArtifact(t)

		anchor := newMinisignKeypair(t)
		signer := newMinisignKeypair(t)
		publishTrustDoc(t, repoDir, "native", anchor, 1,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
		// The index entry is platform-agnostic, but the publisher's signature
		// binds these bytes to darwin/arm64.
		publishIndex(t, repoDir, signer, 1, indexPkg{name: "hello", version: "1.0.0", artifact: art})
		writeArtifact(t, repoDir, signer, "hello", "1.0.0", "darwin/arm64", "", art)

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHello(t, srv.URL, writeTrustRoot(t, anchor))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("claims platform darwin/arm64, expected any"))
	})

	It("rejects an artifact signature whose comment omits platform=", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		repoDir := t.TempDir()
		art := helloArtifact(t)

		anchor := newMinisignKeypair(t)
		signer := newMinisignKeypair(t)
		publishTrustDoc(t, repoDir, "native", anchor, 1,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
		publishIndex(t, repoDir, signer, 1, indexPkg{name: "hello", version: "1.0.0", artifact: art})
		// An old-format claim: correctly signed and otherwise matching, but with
		// no platform. Absence must not be read as "any".
		Expect(os.WriteFile(filepath.Join(repoDir, "hello-1.0.0.tar.zst"), art, 0o644)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(repoDir, "hello-1.0.0.tar.zst.minisig"),
			[]byte(signer.signWithComment(art, "name=hello version=1.0.0 hash="+blakeHash(art))), 0o644)).To(Succeed())

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHello(t, srv.URL, writeTrustRoot(t, anchor))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("artifact signature comment missing platform"))
	})

	It("rotates: old key rejected, new key accepted", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		repoDir := t.TempDir()
		art := helloArtifact(t)

		anchor := newMinisignKeypair(t)
		oldKey := newMinisignKeypair(t)
		newKey := newMinisignKeypair(t)
		// Rotated doc: only newKey is active (oldKey removed).
		publishTrustDoc(t, repoDir, "native", anchor, 2,
			[]trustKeySpec{{kp: newKey, roles: []string{"index", "artifact"}}}, nil)
		publishIndex(t, repoDir, newKey, 2, indexPkg{name: "hello", version: "1.0.0", artifact: art})

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		trustRoot := writeTrustRoot(t, anchor)

		// Artifact signed by the OLD (now removed) key -> rejected.
		writeArtifact(t, repoDir, oldKey, "hello", "1.0.0", "", "", art)
		_, err := applyHello(t, srv.URL, trustRoot)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not in the trust set"))

		// Re-sign with the NEW key -> accepted.
		writeArtifact(t, repoDir, newKey, "hello", "1.0.0", "", "", art)
		out, err := applyHello(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("applied generation"))
	})

	It("rejects an index serial rollback", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		repoDir := t.TempDir()
		art := helloArtifact(t)

		anchor := newMinisignKeypair(t)
		signer := newMinisignKeypair(t)
		publishTrustDoc(t, repoDir, "native", anchor, 1,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
		writeArtifact(t, repoDir, signer, "hello", "1.0.0", "", "", art)
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		trustRoot := writeTrustRoot(t, anchor)

		// First apply at index serial 5 succeeds and persists last-seen=5.
		publishIndex(t, repoDir, signer, 5, indexPkg{name: "hello", version: "1.0.0", artifact: art})
		out, err := applyHello(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("applied generation"))

		// Republish an OLDER index serial 4 -> rollback rejected.
		publishIndex(t, repoDir, signer, 4, indexPkg{name: "hello", version: "1.0.0", artifact: art})
		_, err = applyHello(t, srv.URL, trustRoot)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("rollback"))
	})

	It("rejects a trust serial rollback that would re-trust a revoked key", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		repoDir := t.TempDir()
		art := helloArtifact(t)

		anchor := newMinisignKeypair(t)
		idxKey := newMinisignKeypair(t)
		artKey := newMinisignKeypair(t)
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		trustRoot := writeTrustRoot(t, anchor)

		// Trust serial 2 REVOKES artKey; index also at serial 2. apply records
		// last-seen trust serial = 2. The artifact (signed by artKey) is rejected,
		// but the trust document itself is accepted and its serial persisted.
		publishTrustDoc(t, repoDir, "native", anchor, 2,
			[]trustKeySpec{{kp: idxKey, roles: []string{"index"}}}, []string{artKey.keyIDHex()})
		publishIndex(t, repoDir, idxKey, 2, indexPkg{name: "hello", version: "1.0.0", artifact: art})
		writeArtifact(t, repoDir, artKey, "hello", "1.0.0", "", "", art)
		_, err := applyHello(t, srv.URL, trustRoot)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("revoked"))

		// Attacker replays the OLD trust doc (serial 1) that still trusts artKey ->
		// trust-document rollback rejected before the revoked key can be re-trusted.
		publishTrustDoc(t, repoDir, "native", anchor, 1,
			[]trustKeySpec{
				{kp: idxKey, roles: []string{"index"}},
				{kp: artKey, roles: []string{"artifact"}},
			}, nil)
		_, err = applyHello(t, srv.URL, trustRoot)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("rollback"))
	})

	It("accepts an out-of-band trust document and rejects tampering", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		repoDir := t.TempDir()
		art := helloArtifact(t)

		anchor := newMinisignKeypair(t)
		signer := newMinisignKeypair(t)
		// Publish index + artifact in-band, but NOT trust.json (airgap: no fetch).
		publishIndex(t, repoDir, signer, 1, indexPkg{name: "hello", version: "1.0.0", artifact: art})
		writeArtifact(t, repoDir, signer, "hello", "1.0.0", "", "", art)
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		// Write the signed trust document to a LOCAL path and reference it via trust_doc.
		oobDir := t.TempDir()
		docPath := filepath.Join(oobDir, "native.trust")
		publishTrustDocToPath(t, docPath, "native", anchor, 1,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
		trustRoot := writeTrustRoot(t, anchor)

		profile := "schema: polypkg.spec/v1\nname: oob\n" +
			"scopes:\n  user:\n    substrate: store\n    prefix: $XDG_DATA_HOME/polypkg\n" +
			"sources:\n  order: [native]\n  native:\n    type: polypkg-native\n" +
			"    url: " + srv.URL + "\n    trust_root: " + trustRoot + "\n    trust_doc: " + docPath + "\n" +
			"packages:\n  user:\n    hello:\n      version: \"=1.0.0\"\n"
		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())

		cmd := cli.NewRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"apply", profilePath})
		Expect(cmd.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("applied generation"))

		// Tampering the local doc (flip a byte) must make a re-apply fail.
		raw, err := os.ReadFile(docPath)
		Expect(err).NotTo(HaveOccurred())
		raw[len(raw)/2] ^= 0xff
		Expect(os.WriteFile(docPath, raw, 0o644)).To(Succeed())
		reapplyCmd := cli.NewRootCmd()
		reapplyCmd.SilenceUsage, reapplyCmd.SilenceErrors = true, true
		reapplyCmd.SetOut(&bytes.Buffer{})
		reapplyCmd.SetErr(&bytes.Buffer{})
		reapplyCmd.SetArgs([]string{"apply", profilePath})
		Expect(reapplyCmd.Execute()).To(HaveOccurred())
	})
})
