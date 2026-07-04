package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// Guards the poisoned-artifact-cache eviction fix: the consumer's artifact
// cache is keyed by base name only and cache hits were served with no
// validation. A repository that republishes DIFFERENT bytes under the SAME
// artifact path (polypkg's own publisher cannot — pool paths are
// content-addressed — but hand-rolled/foreign layouts can) therefore wedged
// the client permanently: the stale cached bytes failed signature/hash
// verification on every install, and nothing ever evicted the entry.
//
// The journey publishes widget 1.0.0 (content-A) at the base-name pool path
// widget-1.0.0.tar.zst — deliberately NOT content-addressed — installs it
// (populating the cache with A), then republishes the SAME path with
// content-B at serial 2 under the same keys and reinstalls. The reinstall
// must fetch fresh bytes and succeed with content-B; pre-fix it failed with
// a permanent ArtifactSignatureError.
var _ = Describe("poisoned artifact cache eviction", Ordered, func() {
	var (
		anchor, signer       minisignKeypair
		repoDir, srvURL      string
		trustRoot            string
		artifactA, artifactB []byte
		dataHome             string
		cacheFile            string
	)

	// activeFile is widget's placed file read THROUGH the active symlink —
	// the bytes a user's shell actually executes for the current generation.
	activeFile := func() string {
		return filepath.Join(dataHome, "polypkg", "active", "widget", "bin", "widget")
	}

	BeforeAll(func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		dataHome = os.Getenv("XDG_DATA_HOME")
		// FetchCatalog keys the artifact cache by source name under the state
		// home; init records the default source name "native".
		cacheFile = filepath.Join(os.Getenv("XDG_STATE_HOME"), "polypkg", "cache", "native", "widget-1.0.0.tar.zst")

		anchor = newMinisignKeypair(t)
		signer = newMinisignKeypair(t)
		repoDir = t.TempDir()

		// Same name, same version, same published path, different bytes.
		artifactA = buildPkg(t, "widget", "1.0.0", "content-A")
		artifactB = buildPkg(t, "widget", "1.0.0", "content-B")

		publishTrustDoc(t, repoDir, "native", anchor, 1,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
		publishIndex(t, repoDir, signer, 1,
			indexPkg{name: "widget", version: "1.0.0", artifact: artifactA})
		writeArtifact(t, repoDir, signer, "widget", "1.0.0", "", artifactA)
		trustRoot = writeTrustRoot(t, anchor)

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)
		srvURL = srv.URL

		profile := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "polypkg", "profile.yaml")
		GinkgoT().Setenv("POLYPKG_PROFILE", profile)
		out, err := runCmd("init", "--source-url", srvURL, "--trust-root-file", trustRoot)
		Expect(err).NotTo(HaveOccurred(), "init: %s", out)
	})

	It("installs content A and populates the artifact cache", func() {
		out, err := runCmd("install", "widget@=1.0.0")
		Expect(err).NotTo(HaveOccurred(), "install widget: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))

		body, rerr := os.ReadFile(activeFile())
		Expect(rerr).NotTo(HaveOccurred(), "read placed file via active symlink")
		Expect(string(body)).To(Equal("content-A"))

		cached, cerr := os.ReadFile(cacheFile)
		Expect(cerr).NotTo(HaveOccurred(), "artifact cache entry must exist after install")
		Expect(cached).To(Equal(artifactA), "cache must hold the content-A bytes")
	})

	It("reinstalls successfully after a same-path republish (the regression)", func() {
		// Republish content-B at serial 2 under the SAME path and keys —
		// exactly the hand-rolled-repo shape the content-addressed pool avoids.
		t := GinkgoTB()
		publishTrustDoc(t, repoDir, "native", anchor, 2,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
		publishIndex(t, repoDir, signer, 2,
			indexPkg{name: "widget", version: "1.0.0", artifact: artifactB})
		writeArtifact(t, repoDir, signer, "widget", "1.0.0", "", artifactB)

		out, err := runCmd("remove", "widget") // auto-applies generation 2
		Expect(err).NotTo(HaveOccurred(), "remove widget: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))

		// Pre-fix: the cache served stale content-A bytes against the fresh
		// content-B signature, failing verification permanently.
		out, err = runCmd("install", "widget@=1.0.0")
		Expect(err).NotTo(HaveOccurred(),
			"reinstall must evict the stale cache entry and fetch fresh bytes: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))

		body, rerr := os.ReadFile(activeFile())
		Expect(rerr).NotTo(HaveOccurred(), "read placed file via active symlink")
		Expect(string(body)).To(Equal("content-B"))
	})

	It("leaves the fresh bytes in the cache so subsequent installs stay healthy", func() {
		cached, err := os.ReadFile(cacheFile)
		Expect(err).NotTo(HaveOccurred(), "artifact cache entry must exist after refetch")
		Expect(cached).To(Equal(artifactB), "cache must hold the refetched content-B bytes")

		// Second install from the (now healthy) cache must also succeed.
		out, rerr := runCmd("remove", "widget")
		Expect(rerr).NotTo(HaveOccurred(), "remove widget: %s", out)
		out, rerr = runCmd("install", "widget@=1.0.0")
		Expect(rerr).NotTo(HaveOccurred(), "install from healthy cache: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))
	})
})

// Guards the same eviction fix on the ATTESTATION fetch path: attestation
// blobs are fetched through the same base-name-keyed cache as artifacts, so a
// same-path attestation republish (the artifact republish forces one — the
// re-signed statement binds the new artifact digest) wedged the client the
// same way: stale cached statement bytes against the fresh signature failed
// verification on every install, and nothing ever evicted the entry.
//
// The journey publishes gizmo 1.0.0 (content-A) plus its attestation at the
// base-name paths gizmo-1.0.0.tar.zst / gizmo-1.0.0.att.json — deliberately
// NOT content-addressed — installs it (poisoning both caches), republishes
// content-B with a re-signed attestation at the SAME paths at serial 2, and
// reinstalls. The artifact half heals via the existing fix; pre-fix the
// attestation half then wedged with a permanent signature mismatch.
var _ = Describe("poisoned attestation cache eviction", Ordered, func() {
	var (
		anchor, signer       minisignKeypair
		repoDir, srvURL      string
		trustRoot            string
		artifactA, artifactB []byte
		attA, attB           []byte
		dataHome             string
		attCacheFile         string
	)

	activeFile := func() string {
		return filepath.Join(dataHome, "polypkg", "active", "gizmo", "bin", "gizmo")
	}

	// publishAttestation signs an in-toto statement binding artifact's digest
	// and publishes it at the base-name pool path gizmo-1.0.0.att.json (plus
	// .minisig), returning the canonical bytes and the index ref for them.
	publishAttestation := func(artifact []byte) ([]byte, schema.AttestationRef) {
		digest := strings.TrimPrefix(blakeHash(artifact), "blake3:")
		st := attest.AssembleStatement("gizmo-1.0.0.tar.zst", digest, json.RawMessage(`{"runs":[]}`))
		attBytes, err := st.CanonicalJSON()
		Expect(err).NotTo(HaveOccurred())
		full := filepath.Join(repoDir, "gizmo-1.0.0.att.json")
		Expect(os.WriteFile(full, attBytes, 0o644)).To(Succeed())
		Expect(os.WriteFile(full+".minisig", []byte(signer.signArtifact("gizmo", "1.0.0", attBytes)), 0o644)).To(Succeed())
		return attBytes, schema.AttestationRef{
			PredicateType: attest.PredicateTypeSARIF,
			Artifact:      "gizmo-1.0.0.att.json",
			ContentHash:   blakeHash(attBytes),
		}
	}

	BeforeAll(func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		dataHome = os.Getenv("XDG_DATA_HOME")
		attCacheFile = filepath.Join(os.Getenv("XDG_STATE_HOME"), "polypkg", "cache", "native", "gizmo-1.0.0.att.json")

		anchor = newMinisignKeypair(t)
		signer = newMinisignKeypair(t)
		repoDir = t.TempDir()

		artifactA = buildPkg(t, "gizmo", "1.0.0", "content-A")
		artifactB = buildPkg(t, "gizmo", "1.0.0", "content-B")

		publishTrustDoc(t, repoDir, "native", anchor, 1,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact", "attestation"}}}, nil)
		var refA schema.AttestationRef
		attA, refA = publishAttestation(artifactA)
		publishIndex(t, repoDir, signer, 1,
			indexPkg{name: "gizmo", version: "1.0.0", artifact: artifactA, attestations: []schema.AttestationRef{refA}})
		writeArtifact(t, repoDir, signer, "gizmo", "1.0.0", "", artifactA)
		trustRoot = writeTrustRoot(t, anchor)

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)
		srvURL = srv.URL

		profile := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "polypkg", "profile.yaml")
		GinkgoT().Setenv("POLYPKG_PROFILE", profile)
		out, err := runCmd("init", "--source-url", srvURL, "--trust-root-file", trustRoot)
		Expect(err).NotTo(HaveOccurred(), "init: %s", out)
	})

	It("installs attested content A and populates the attestation cache", func() {
		out, err := runCmd("install", "gizmo@=1.0.0")
		Expect(err).NotTo(HaveOccurred(), "install gizmo: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))

		cached, cerr := os.ReadFile(attCacheFile)
		Expect(cerr).NotTo(HaveOccurred(), "attestation cache entry must exist after install")
		Expect(cached).To(Equal(attA), "cache must hold the serial-1 attestation bytes")
	})

	It("reinstalls successfully after a same-path attestation republish (the regression)", func() {
		// Republish content-B at serial 2: same artifact path, same attestation
		// path, re-signed statement binding the new digest.
		t := GinkgoTB()
		publishTrustDoc(t, repoDir, "native", anchor, 2,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact", "attestation"}}}, nil)
		var refB schema.AttestationRef
		attB, refB = publishAttestation(artifactB)
		publishIndex(t, repoDir, signer, 2,
			indexPkg{name: "gizmo", version: "1.0.0", artifact: artifactB, attestations: []schema.AttestationRef{refB}})
		writeArtifact(t, repoDir, signer, "gizmo", "1.0.0", "", artifactB)

		out, err := runCmd("remove", "gizmo") // auto-applies the next generation
		Expect(err).NotTo(HaveOccurred(), "remove gizmo: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))

		// Pre-fix: the artifact cache healed, then the attestation cache served
		// stale serial-1 statement bytes against the fresh serial-2 signature,
		// failing verification permanently.
		out, err = runCmd("install", "gizmo@=1.0.0")
		Expect(err).NotTo(HaveOccurred(),
			"reinstall must evict the stale attestation cache entry and fetch fresh bytes: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))

		body, rerr := os.ReadFile(activeFile())
		Expect(rerr).NotTo(HaveOccurred(), "read placed file via active symlink")
		Expect(string(body)).To(Equal("content-B"))
	})

	It("leaves the fresh attestation bytes in the cache so subsequent installs stay healthy", func() {
		cached, err := os.ReadFile(attCacheFile)
		Expect(err).NotTo(HaveOccurred(), "attestation cache entry must exist after refetch")
		Expect(cached).To(Equal(attB), "cache must hold the refetched serial-2 attestation bytes")

		out, rerr := runCmd("remove", "gizmo")
		Expect(rerr).NotTo(HaveOccurred(), "remove gizmo: %s", out)
		out, rerr = runCmd("install", "gizmo@=1.0.0")
		Expect(rerr).NotTo(HaveOccurred(), "install from healthy cache: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))
	})
})
