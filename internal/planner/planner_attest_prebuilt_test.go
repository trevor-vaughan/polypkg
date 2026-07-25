package planner_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// buildSignedPrebuiltNativeRepo builds a real signed polypkg repo whose single
// package (hello 1.0.0) is ingested as a PREBUILT artifact carrying a
// native_attestation: a JCS-canonical in-toto SARIF statement whose subject
// digest binds the packed artifact (the `pkg build` <name>-<version>.att.json
// preview, Task 3). It returns the output directory (used as the source URL)
// and the path to its trust_root.pub. This is the prebuilt analogue of
// buildSignedLocalRepo; the consumer must not be able to tell the two apart.
func buildSignedPrebuiltNativeRepo(t testing.TB, sourceName string) (outputDir, trustRoot string) {
	t.Helper()
	root := t.TempDir()
	keyDir := t.TempDir() // outside the output dir (guardKeyNotInOutput)

	// Author a package source and pack it into the prebuilt artifact tarball.
	originDir := filepath.Join(root, "origin", "hello")
	if err := os.MkdirAll(filepath.Join(originDir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(originDir, "polypkg.yaml"),
		[]byte("schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(originDir, "content", "bin", "hello"),
		[]byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	artifact, _, err := repo.PackArtifact(originDir)
	if err != nil {
		t.Fatalf("pack prebuilt artifact: %v", err)
	}

	// Stage the artifact and an (empty) carried-attestations directory so the
	// only attestation on the package is the native one under test.
	stg := filepath.Join(root, "staging", "hello")
	attDir := filepath.Join(stg, "atts")
	if err := os.MkdirAll(attDir, 0o755); err != nil {
		t.Fatal(err)
	}
	artPath := filepath.Join(stg, "hello.tar.zst")
	if err := os.WriteFile(artPath, artifact, 0o644); err != nil {
		t.Fatal(err)
	}

	// Bind the native SARIF preview to the packed artifact's content-hash.
	hex := strings.TrimPrefix(repo.ContentHash(artifact), "blake3:")
	st := attest.AssembleStatement("hello-1.0.0.tar.zst", hex, json.RawMessage(`{"runs":[]}`))
	canon, err := st.CanonicalJSON()
	if err != nil {
		t.Fatalf("canonicalize native attestation: %v", err)
	}
	nativePath := filepath.Join(stg, "native.att.json")
	if err := os.WriteFile(nativePath, canon, 0o644); err != nil {
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
		"packages:\n  hello:\n    prebuilt:\n" +
		"      artifact: " + artPath + "\n" +
		"      attestations: " + attDir + "\n" +
		"      native_attestation: " + nativePath + "\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	if _, err := b.Build(repo.BuildOptions{}); err != nil {
		t.Fatalf("Build prebuilt with native attestation: %v", err)
	}

	outputDir = filepath.Join(root, "public")
	trustRoot = filepath.Join(outputDir, "trust_root.pub")
	return outputDir, trustRoot
}

var _ = Describe("Prebuilt package native attestation (consumer verify)", func() {
	It("verifies end-to-end, indistinguishable from a source-minted native attestation", func() {
		out, tr := buildSignedPrebuiltNativeRepo(GinkgoTB(), "repo")

		// Locate the published native SARIF ref so we can assert the recorded
		// verdict pins exactly its content-hash.
		var nativeRef schema.AttestationRef
		found := false
		for _, ref := range readPublishedIndex(GinkgoTB(), out).Packages["hello"][0].Attestations {
			if ref.Kind == schema.KindNativeJCS && ref.PredicateType == attest.PredicateTypeSARIF {
				nativeRef = ref
				found = true
			}
		}
		Expect(found).To(BeTrue(), "published index has no native-jcs SARIF ref for the prebuilt package")

		p := profileForLocalSource("repo", out, tr)
		res, err := planner.Plan(GinkgoT().Context(), p, planner.Options{
			Scope:             "user",
			DataHome:          GinkgoT().TempDir(),
			StateHome:         GinkgoT().TempDir(),
			AttestationPolicy: "require",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.AttestationWarnings).To(BeEmpty())
		Expect(res.Manifest.Entries).To(HaveLen(1))

		att := res.Manifest.Entries[0].Attestation
		Expect(att).NotTo(BeNil())
		// The prebuilt package's native attestation verifies exactly like a
		// source-minted one: verified status, the SARIF predicate recorded, and
		// the recorded hash pinned to the published native ref.
		Expect(att.Status).To(Equal("verified"))
		Expect(att.PredicateTypes).To(ConsistOf(attest.PredicateTypeSARIF))
		Expect(att.AttestationHash).To(Equal(nativeRef.ContentHash))
		Expect(att.PolicyAtInstall).To(Equal("require"))
		// Only the native attestation is present — no carried envelopes.
		Expect(att.CarriedBindings).To(BeEmpty())
	})
})
