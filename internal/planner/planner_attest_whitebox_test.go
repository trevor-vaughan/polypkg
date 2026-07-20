package planner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"lukechampine.com/blake3"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/source"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// fakeAttBackend serves canned bytes/signatures for attestation paths.
type fakeAttBackend struct {
	data map[string][]byte
	sigs map[string]string
}

func (f *fakeAttBackend) Name() string { return "fake" }

func (f *fakeAttBackend) Fetch(_ context.Context, artifact string) ([]byte, error) {
	b, ok := f.data[artifact]
	if !ok {
		return nil, fmt.Errorf("no such artifact %q", artifact)
	}
	return b, nil
}

func (f *fakeAttBackend) FetchSignature(_ context.Context, artifact string) (string, error) {
	s, ok := f.sigs[artifact]
	if !ok {
		return "", fmt.Errorf("no such signature %q", artifact)
	}
	return s, nil
}

func (f *fakeAttBackend) FetchIndex(context.Context) ([]byte, string, error) {
	return nil, "", errors.New("not used")
}

func (f *fakeAttBackend) FetchTrustDoc(context.Context) ([]byte, string, error) {
	return nil, "", errors.New("not used")
}

func (f *fakeAttBackend) FetchTrustBundle(context.Context) ([]byte, string, error) {
	return nil, "", source.ErrMetadataAbsent
}

func (f *fakeAttBackend) FetchRevocationList(context.Context) ([]byte, string, error) {
	return nil, "", source.ErrMetadataAbsent
}

// fakeAttRefetchBackend adds the source.ArtifactRefetcher capability to
// fakeAttBackend: RefetchArtifact serves from fresh (the post-eviction bytes)
// and counts calls so tests can pin the retry to exactly once.
type fakeAttRefetchBackend struct {
	fakeAttBackend
	fresh     map[string][]byte
	refetches int
}

func (f *fakeAttRefetchBackend) RefetchArtifact(_ context.Context, artifact string) ([]byte, error) {
	f.refetches++
	b, ok := f.fresh[artifact]
	if !ok {
		return nil, fmt.Errorf("no fresh artifact %q", artifact)
	}
	return b, nil
}

// fakeKeyring returns preset claims (or an error), recording the role it was
// asked to verify under. When bindBytes is set the returned claims' hash is
// recomputed from the bytes handed to Verify, so a single keyring can bind the
// claims of every ref it is asked about (needed when native and carried refs
// carry different bytes in one verifyAttestations call).
type fakeKeyring struct {
	claims    trust.Claims
	err       error
	bindBytes bool
	roleSeen  trust.Role
}

func (f *fakeKeyring) Verify(role trust.Role, data []byte, _ string) (trust.Claims, error) {
	f.roleSeen = role
	if f.err != nil {
		return trust.Claims{}, f.err
	}
	if f.bindBytes {
		bound := trust.Claims{Values: map[string]string{}}
		for k, v := range f.claims.Values {
			bound.Values[k] = v
		}
		h := blake3.New(32, nil)
		_, _ = h.Write(data)
		bound.Values["hash"] = "blake3:" + hex.EncodeToString(h.Sum(nil))
		return bound, nil
	}
	return f.claims, nil
}

func blake3Hex(b []byte) string {
	h := blake3.New(32, nil)
	_, _ = h.Write(b)
	return "blake3:" + hex.EncodeToString(h.Sum(nil))
}

var _ = Describe("verifyAttestations binding checks", func() {
	const artifactDigestHex = "0011aabb" // bare hex the statement subject binds

	// statementBytes returns canonical attestation bytes whose subject binds
	// digestHex under predicate type SARIF.
	statementBytes := func(digestHex string) []byte {
		st := attest.AssembleStatement("hello-1.0.0.tar.zst", digestHex, json.RawMessage(`{"runs":[]}`))
		b, err := st.CanonicalJSON()
		Expect(err).NotTo(HaveOccurred())
		return b
	}

	// resolvedFor builds the Resolved entry pointing one AttestationRef at the
	// given attestation bytes.
	resolvedFor := func(attBytes []byte, predicateType string) resolver.Resolved {
		return resolver.Resolved{
			Name: "hello", Version: "1.0.0",
			ContentHash: "blake3:" + artifactDigestHex,
			Attestations: []schema.AttestationRef{{
				PredicateType: predicateType,
				Artifact:      "pool/x.att.json",
				ContentHash:   blake3Hex(attBytes),
			}},
		}
	}

	backendFor := func(attBytes []byte) *fakeAttBackend {
		return &fakeAttBackend{
			data: map[string][]byte{"pool/x.att.json": attBytes},
			sigs: map[string]string{"pool/x.att.json": "sig"},
		}
	}

	goodClaims := func(attBytes []byte) trust.Claims {
		return trust.Claims{Values: map[string]string{
			"name": "hello", "version": "1.0.0", "hash": blake3Hex(attBytes),
		}}
	}

	It("verifies under the attestation role with fully bound claims", func() {
		attBytes := statementBytes(artifactDigestHex)
		kr := &fakeKeyring{claims: goodClaims(attBytes)}
		state, _, warn, err := verifyAttestations(context.Background(), backendFor(attBytes), kr, nil, resolvedFor(attBytes, attest.PredicateTypeSARIF), "warn")
		Expect(err).NotTo(HaveOccurred())
		Expect(warn).To(BeEmpty())
		Expect(kr.roleSeen).To(Equal(trust.RoleAttestation))
		Expect(state.Status).To(Equal("verified"))
		Expect(state.AttestationHash).To(Equal(blake3Hex(attBytes)))
	})

	It("fails when the keyring rejects (key lacks the attestation role)", func() {
		attBytes := statementBytes(artifactDigestHex)
		kr := &fakeKeyring{err: errors.New("key 0000 lacks role attestation")}
		_, _, _, err := verifyAttestations(context.Background(), backendFor(attBytes), kr, nil, resolvedFor(attBytes, attest.PredicateTypeSARIF), "off")
		Expect(err).To(MatchError(ContainSubstring("attestation signature for hello-1.0.0")))
	})

	It("fails when the claims name a different package (binding mismatch)", func() {
		attBytes := statementBytes(artifactDigestHex)
		claims := goodClaims(attBytes)
		claims.Values["name"] = "evil"
		kr := &fakeKeyring{claims: claims}
		_, _, _, err := verifyAttestations(context.Background(), backendFor(attBytes), kr, nil, resolvedFor(attBytes, attest.PredicateTypeSARIF), "off")
		Expect(err).To(MatchError(ContainSubstring("binding mismatch")))
	})

	It("fails when the claims hash does not match the fetched bytes", func() {
		attBytes := statementBytes(artifactDigestHex)
		claims := goodClaims(attBytes)
		claims.Values["hash"] = "blake3:ffff"
		kr := &fakeKeyring{claims: claims}
		_, _, _, err := verifyAttestations(context.Background(), backendFor(attBytes), kr, nil, resolvedFor(attBytes, attest.PredicateTypeSARIF), "off")
		Expect(err).To(MatchError(ContainSubstring("binding mismatch")))
	})

	It("fails when the statement's predicate type differs from the index ref", func() {
		attBytes := statementBytes(artifactDigestHex)
		kr := &fakeKeyring{claims: goodClaims(attBytes)}
		_, _, _, err := verifyAttestations(context.Background(), backendFor(attBytes), kr, nil, resolvedFor(attBytes, "https://example.com/other/v1"), "off")
		Expect(err).To(MatchError(ContainSubstring("predicate type mismatch")))
	})

	It("fails when the statement subject digest does not match the artifact (validly signed, wrong subject)", func() {
		attBytes := statementBytes("deadbeef") // != artifactDigestHex
		kr := &fakeKeyring{claims: goodClaims(attBytes)}
		_, _, _, err := verifyAttestations(context.Background(), backendFor(attBytes), kr, nil, resolvedFor(attBytes, attest.PredicateTypeSARIF), "off")
		Expect(err).To(MatchError(ContainSubstring("subject digest")))
	})

	It("verifies a multi-subject statement whose binding subject is not first (in-toto: predicate applies to each subject)", func() {
		st := attest.AssembleStatement("other-artifact", "deadbeef", json.RawMessage(`{"runs":[]}`))
		st.Subject = append(st.Subject,
			attest.Subject{Name: "hello-1.0.0.tar.zst", Digest: map[string]string{"blake3": artifactDigestHex}})
		attBytes, err := st.CanonicalJSON()
		Expect(err).NotTo(HaveOccurred())
		kr := &fakeKeyring{claims: goodClaims(attBytes)}
		state, _, warn, err := verifyAttestations(context.Background(), backendFor(attBytes), kr, nil, resolvedFor(attBytes, attest.PredicateTypeSARIF), "off")
		Expect(err).NotTo(HaveOccurred())
		Expect(warn).To(BeEmpty())
		Expect(state.Status).To(Equal("verified"))
	})

	// Staleable failures must evict and refetch ONCE when the backend can:
	// the attestation blob rides the same base-name-keyed cache as artifacts,
	// so a same-path republish otherwise wedges the client permanently.
	Context("poisoned-cache refetch", func() {
		It("heals a staleable binding mismatch by refetching once", func() {
			freshBytes := statementBytes(artifactDigestHex)
			staleBytes := statementBytes("deadbeef") // the pre-republish statement
			be := &fakeAttRefetchBackend{
				fakeAttBackend: *backendFor(staleBytes),
				fresh:          map[string][]byte{"pool/x.att.json": freshBytes},
			}
			// Claims/ref describe the republished attestation; the cached stale
			// bytes hash differently, so the first pass is a binding mismatch.
			kr := &fakeKeyring{claims: goodClaims(freshBytes)}
			state, _, warn, err := verifyAttestations(context.Background(), be, kr, nil, resolvedFor(freshBytes, attest.PredicateTypeSARIF), "warn")
			Expect(err).NotTo(HaveOccurred())
			Expect(warn).To(BeEmpty())
			Expect(be.refetches).To(Equal(1))
			Expect(state.Status).To(Equal("verified"))
			Expect(state.AttestationHash).To(Equal(blake3Hex(freshBytes)))
		})

		It("refetches only once when the fresh bytes still fail", func() {
			freshBytes := statementBytes(artifactDigestHex)
			staleBytes := statementBytes("deadbeef")
			be := &fakeAttRefetchBackend{
				fakeAttBackend: *backendFor(staleBytes),
				// Refetch serves the SAME stale bytes: the repo really is bad.
				fresh: map[string][]byte{"pool/x.att.json": staleBytes},
			}
			kr := &fakeKeyring{claims: goodClaims(freshBytes)}
			_, _, _, err := verifyAttestations(context.Background(), be, kr, nil, resolvedFor(freshBytes, attest.PredicateTypeSARIF), "warn")
			Expect(err).To(MatchError(ContainSubstring("binding mismatch")))
			Expect(be.refetches).To(Equal(1))
		})

		It("does not refetch on a terminal authorization failure", func() {
			attBytes := statementBytes(artifactDigestHex)
			be := &fakeAttRefetchBackend{
				fakeAttBackend: *backendFor(attBytes),
				fresh:          map[string][]byte{"pool/x.att.json": attBytes},
			}
			kr := &fakeKeyring{err: errors.New("key 0000 lacks role attestation")}
			_, _, _, err := verifyAttestations(context.Background(), be, kr, nil, resolvedFor(attBytes, attest.PredicateTypeSARIF), "warn")
			Expect(err).To(MatchError(ContainSubstring("attestation signature for hello-1.0.0")))
			Expect(be.refetches).To(BeZero())
		})
	})

	// Carried external provenance (kind: carried-opaque) is an opaque builder
	// envelope. The consumer transport-verifies it here — publisher signature,
	// claims, content hash against the signed index — but does NOT run the
	// native in-toto statement parse / subject bind over it (a DSSE/SBOM
	// envelope is not a bare in-toto Statement; its subjects are digest-bound
	// after extraction, in a later phase). A carried ref contributes no
	// predicate type to the recorded state.
	Context("carried-opaque refs are transport-verified but not statement-parsed", func() {
		// dsseEnvelope is a builder DSSE envelope (no in-toto _type): the exact
		// shape the native statement parse cannot handle, proving the carried
		// path skips that parse — if it ran ParseStatement, this would hard-error.
		dsseEnvelope := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"eyJ4IjoxfQ==","signatures":[]}`)

		It("stays installable: a carried ref transport-verifies while the native ref also verifies", func() {
			attBytes := statementBytes(artifactDigestHex)
			carriedCH := blake3Hex(dsseEnvelope)
			res := resolver.Resolved{
				Name: "hello", Version: "1.0.0",
				ContentHash: "blake3:" + artifactDigestHex,
				Attestations: []schema.AttestationRef{
					// Carried-opaque FIRST: transport-verified, statement-parse skipped.
					{
						PredicateType: attest.PredicateTypeSARIF,
						Artifact:      "pool/carried.att.json",
						ContentHash:   carriedCH,
						Kind:          schema.KindCarriedOpaque,
					},
					// Native SARIF SECOND: it must still be fetched and verified.
					{
						PredicateType: attest.PredicateTypeSARIF,
						Artifact:      "pool/x.att.json",
						ContentHash:   blake3Hex(attBytes),
						Kind:          schema.KindNativeJCS,
					},
				},
			}
			be := &fakeAttBackend{
				data: map[string][]byte{
					// The carried DSSE bytes transport-verify (bindBytes binds the
					// claims hash to them) but are never handed to ParseStatement.
					"pool/carried.att.json": dsseEnvelope,
					"pool/x.att.json":       attBytes,
				},
				sigs: map[string]string{
					"pool/carried.att.json": "sig",
					"pool/x.att.json":       "sig",
				},
			}
			// bindBytes: the claims hash tracks whichever ref's bytes are verified,
			// so both the carried and native refs bind their own content hash.
			kr := &fakeKeyring{claims: goodClaims(attBytes), bindBytes: true}
			state, _, warn, err := verifyAttestations(context.Background(), be, kr, nil, res, "warn")
			Expect(err).NotTo(HaveOccurred())
			Expect(warn).To(BeEmpty())
			Expect(state.Status).To(Equal("verified"))
			// Only the native SARIF predicate is recorded — the carried ref
			// transport-verifies but contributes no predicate type.
			Expect(state.PredicateTypes).To(ConsistOf(attest.PredicateTypeSARIF))
			Expect(state.PredicateTypes).To(HaveLen(1))
			Expect(state.AttestationHash).To(Equal(blake3Hex(attBytes)))
		})

		It("transport-verifies a carried-only entry without parsing its opaque statement", func() {
			// Baseline: the SAME DSSE bytes fail the NATIVE verifyAttestation (no
			// in-toto _type), proving the carried path's statement-parse skip is
			// what keeps this installable.
			_, _, direct := verifyAttestation(dsseEnvelope, "sig",
				&fakeKeyring{claims: trust.Claims{Values: map[string]string{
					"name": "hello", "version": "1.0.0", "hash": blake3Hex(dsseEnvelope),
				}}},
				resolver.Resolved{Name: "hello", Version: "1.0.0", ContentHash: "blake3:" + artifactDigestHex},
				schema.AttestationRef{PredicateType: attest.PredicateTypeSARIF, ContentHash: blake3Hex(dsseEnvelope)})
			Expect(direct).To(HaveOccurred()) // baseline: opaque bytes are unparseable

			res := resolver.Resolved{
				Name: "hello", Version: "1.0.0",
				ContentHash: "blake3:" + artifactDigestHex,
				Attestations: []schema.AttestationRef{{
					PredicateType: attest.PredicateTypeSARIF,
					Artifact:      "pool/carried.att.json",
					ContentHash:   blake3Hex(dsseEnvelope),
					Kind:          schema.KindCarriedOpaque,
				}},
			}
			be := &fakeAttBackend{
				data: map[string][]byte{"pool/carried.att.json": dsseEnvelope},
				sigs: map[string]string{"pool/carried.att.json": "sig"},
			}
			// The carried ref still transport-verifies (claims bound to its bytes);
			// a carried-only entry records "verified" with no predicate types.
			kr := &fakeKeyring{claims: goodClaims(dsseEnvelope), bindBytes: true}
			state, _, warn, err := verifyAttestations(context.Background(), be, kr, nil, res, "warn")
			Expect(err).NotTo(HaveOccurred())
			Expect(warn).To(BeEmpty())
			Expect(state.Status).To(Equal("verified"))
			Expect(state.PredicateTypes).To(BeEmpty())
		})

		It("fails a carried ref that does not transport-verify (opaque bytes are no longer a free pass)", func() {
			// A carried ref whose publisher signature/claims do not bind is now a
			// terminal error — previously it was silently skipped.
			res := resolver.Resolved{
				Name: "hello", Version: "1.0.0",
				ContentHash: "blake3:" + artifactDigestHex,
				Attestations: []schema.AttestationRef{{
					PredicateType: attest.PredicateTypeSARIF,
					Artifact:      "pool/carried.att.json",
					ContentHash:   blake3Hex(dsseEnvelope),
					Kind:          schema.KindCarriedOpaque,
				}},
			}
			be := &fakeAttBackend{
				data: map[string][]byte{"pool/carried.att.json": dsseEnvelope},
				sigs: map[string]string{"pool/carried.att.json": "sig"},
			}
			// Claims name a different package: the transport binding check fails.
			claims := goodClaims(dsseEnvelope)
			claims.Values["name"] = "evil"
			kr := &fakeKeyring{claims: claims, bindBytes: true}
			_, _, _, err := verifyAttestations(context.Background(), be, kr, nil, res, "warn")
			Expect(err).To(MatchError(ContainSubstring("binding mismatch")))
		})
	})

	It("fails a multi-subject statement when NO subject matches the artifact digest", func() {
		st := attest.AssembleStatement("other-artifact", "deadbeef", json.RawMessage(`{"runs":[]}`))
		st.Subject = append(st.Subject,
			attest.Subject{Name: "second", Digest: map[string]string{"blake3": "cafef00d"}},
			// A blake3-less trailing subject must be skipped, not crash the scan.
			attest.Subject{Name: "third", Digest: map[string]string{"sha256": "aabb"}})
		attBytes, err := st.CanonicalJSON()
		Expect(err).NotTo(HaveOccurred())
		kr := &fakeKeyring{claims: goodClaims(attBytes)}
		_, _, _, err = verifyAttestations(context.Background(), backendFor(attBytes), kr, nil, resolvedFor(attBytes, attest.PredicateTypeSARIF), "off")
		Expect(err).To(MatchError(ContainSubstring("subject digest")))
	})
})

var _ = Describe("bindCarriedRefs install-time binding", func() {
	// dsseCarried wraps an in-toto SLSA statement (one subject over sha256hex,
	// named nameHint) in a minimal DSSE envelope — the shape
	// ExtractCarriedSubjects accepts.
	dsseCarried := func(nameHint, sha256hex string) []byte {
		stmt := fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v1",`+
			`"subject":[{"name":%q,"digest":{"sha256":%q}}],`+
			`"predicateType":"https://slsa.dev/provenance/v1","predicate":{}}`, nameHint, sha256hex)
		payload := base64.StdEncoding.EncodeToString([]byte(stmt))
		env := fmt.Sprintf(`{"payloadType":"application/vnd.in-toto+json","payload":%q,"signatures":[]}`, payload)
		return []byte(env)
	}

	sha256Of := func(b []byte) string {
		s := sha256.Sum256(b)
		return hex.EncodeToString(s[:])
	}

	// writeExtracted creates a pkgRoot/content tree with the given files and
	// returns pkgRoot.
	writeExtracted := func(files map[string][]byte) string {
		pkgRoot, err := os.MkdirTemp("", "pkgroot-*")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = os.RemoveAll(pkgRoot) })
		for rel, body := range files {
			full := filepath.Join(pkgRoot, "content", rel)
			Expect(os.MkdirAll(filepath.Dir(full), 0o700)).To(Succeed())
			Expect(os.WriteFile(full, body, 0o600)).To(Succeed())
		}
		return pkgRoot
	}

	It("binds a carried subject to an extracted content file and records the tier", func() {
		body := []byte("payload bytes")
		pkgRoot := writeExtracted(map[string][]byte{"bin/hello": body})
		env := dsseCarried("advisory-name", sha256Of(body))
		attState := &schema.AttestationState{Status: "verified", PolicyAtInstall: "warn"}
		refs := []carriedRef{{
			ref: schema.AttestationRef{
				PredicateType: "https://slsa.dev/provenance/v1",
				Kind:          schema.KindCarriedOpaque,
				Format:        schema.FormatSLSAProvenance,
				Artifact:      "pool/c.att.json",
			},
			bytes: env,
		}}
		Expect(bindCarriedRefs(refs, []byte("tarball"), pkgRoot, nil, nil, nil, attState)).To(Succeed())
		Expect(attState.CarriedBindings).To(HaveLen(1))
		// dsseCarried wraps a DSSE envelope with no signatures and no bundle is
		// passed here, so its builder signature cannot be verified: this is the
		// binding-logic test, not the builder-signature-tiering test (see
		// planner_attest_test.go's "carriage builder-signature verification").
		Expect(attState.CarriedBindings[0].Tier).To(Equal(schema.CarriedTierVerifiedTransportOnly))
		Expect(attState.CarriedBindings[0].SubjectScope).To(Equal("content:bin/hello"))
		Expect(attState.CarriedBindings[0].Format).To(Equal(schema.FormatSLSAProvenance))
	})

	It("binds a carried subject to the artifact tarball", func() {
		tarball := []byte("the whole tar.zst")
		pkgRoot := writeExtracted(map[string][]byte{"bin/hello": []byte("unrelated")})
		env := dsseCarried("artifact", sha256Of(tarball))
		attState := &schema.AttestationState{Status: "verified", PolicyAtInstall: "warn"}
		refs := []carriedRef{{ref: schema.AttestationRef{Kind: schema.KindCarriedOpaque, Artifact: "pool/c.att.json"}, bytes: env}}
		Expect(bindCarriedRefs(refs, tarball, pkgRoot, nil, nil, nil, attState)).To(Succeed())
		Expect(attState.CarriedBindings[0].SubjectScope).To(Equal("artifact"))
	})

	It("fails closed when the extracted bytes do not match the carried subject", func() {
		pkgRoot := writeExtracted(map[string][]byte{"bin/hello": []byte("TAMPERED bytes")})
		env := dsseCarried("bin/hello", sha256Of([]byte("original honest bytes")))
		attState := &schema.AttestationState{Status: "verified", PolicyAtInstall: "warn"}
		refs := []carriedRef{{ref: schema.AttestationRef{Kind: schema.KindCarriedOpaque, Artifact: "pool/c.att.json"}, bytes: env}}
		err := bindCarriedRefs(refs, []byte("tarball"), pkgRoot, nil, nil, nil, attState)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not bind the installed bytes"))
	})

	It("does not let a symlinked subject file satisfy a binding", func() {
		body := []byte("payload bytes")
		pkgRoot := writeExtracted(map[string][]byte{"real": body})
		// Place a symlink at the subject path pointing at the real file. Because
		// binding is by digest over the set of REGULAR-file targets, the symlink
		// is never offered as a target; the real file still holds the bytes, so
		// the subject binds to content:real, NOT the symlink path.
		link := filepath.Join(pkgRoot, "content", "bin", "hello")
		Expect(os.MkdirAll(filepath.Dir(link), 0o700)).To(Succeed())
		Expect(os.Symlink(filepath.Join(pkgRoot, "content", "real"), link)).To(Succeed())
		env := dsseCarried("bin/hello", sha256Of(body))
		attState := &schema.AttestationState{Status: "verified", PolicyAtInstall: "warn"}
		refs := []carriedRef{{ref: schema.AttestationRef{Kind: schema.KindCarriedOpaque, Artifact: "pool/c.att.json"}, bytes: env}}
		Expect(bindCarriedRefs(refs, []byte("tarball"), pkgRoot, nil, nil, nil, attState)).To(Succeed())
		Expect(attState.CarriedBindings[0].SubjectScope).To(Equal("content:real"))
	})

	It("is a no-op with no carried refs", func() {
		attState := &schema.AttestationState{Status: "verified", PolicyAtInstall: "warn"}
		Expect(bindCarriedRefs(nil, []byte("tarball"), "/nonexistent", nil, nil, nil, attState)).To(Succeed())
		Expect(attState.CarriedBindings).To(BeEmpty())
	})

	It("refuses when the index ref predicate type disagrees with the signed payload (G9)", func() {
		body := []byte("payload bytes")
		pkgRoot := writeExtracted(map[string][]byte{"bin/hello": body})
		env := dsseCarried("bin/hello", sha256Of(body)) // payload predicateType is slsa/provenance/v1
		attState := &schema.AttestationState{Status: "verified", PolicyAtInstall: "warn"}
		refs := []carriedRef{{
			ref: schema.AttestationRef{
				PredicateType: "https://spdx.dev/Document", // index claims a DIFFERENT type
				Kind:          schema.KindCarriedOpaque,
				Artifact:      "pool/c.att.json",
			},
			bytes: env,
		}}
		err := bindCarriedRefs(refs, []byte("tarball"), pkgRoot, nil, nil, nil, attState)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("predicate type mismatch"))
	})

	It("does not cross-check when the index ref declares no predicate type", func() {
		body := []byte("payload bytes")
		pkgRoot := writeExtracted(map[string][]byte{"bin/hello": body})
		env := dsseCarried("bin/hello", sha256Of(body))
		attState := &schema.AttestationState{Status: "verified", PolicyAtInstall: "warn"}
		refs := []carriedRef{{
			ref:   schema.AttestationRef{Kind: schema.KindCarriedOpaque, Artifact: "pool/c.att.json"}, // no PredicateType
			bytes: env,
		}}
		Expect(bindCarriedRefs(refs, []byte("tarball"), pkgRoot, nil, nil, nil, attState)).To(Succeed())
		Expect(attState.CarriedBindings[0].PredicateType).To(Equal("https://slsa.dev/provenance/v1"))
	})

	// Sigstore carriage (2c-3b): a dev.sigstore.bundle whose inner in-toto subject
	// digest is the sha256 of the extracted file verifies OFFLINE against the
	// source's mirrored SigstoreRoot (selected by the bundle's integrated time),
	// records verified-offline, and captures the Fulcio identity. The fixtures are
	// minted once by internal/attest/testdata/sigstoregen (see that generator).
	Context("carried sigstore bundle", func() {
		readFixture := func(name string) []byte {
			b, err := os.ReadFile(filepath.Join("..", "attest", "testdata", name))
			Expect(err).NotTo(HaveOccurred())
			return b
		}

		It("verifies offline and records verified-offline with the Fulcio identity", func() {
			bundleBytes := readFixture("bindable-bundle.json")
			content := readFixture("bindable-content.bin")
			var sroot schema.SigstoreRoot
			Expect(json.Unmarshal(readFixture("bindable-root.json"), &sroot)).To(Succeed())

			pkgRoot := writeExtracted(map[string][]byte{"bin/app": content})
			tb := trust.NewBundleForTesting(nil, []schema.SigstoreRoot{sroot})
			attState := &schema.AttestationState{Status: "verified", PolicyAtInstall: "warn"}
			refs := []carriedRef{{
				ref: schema.AttestationRef{
					Kind:     schema.KindCarriedOpaque,
					Artifact: "pool/sig.att.json",
					Format:   schema.FormatSigstoreBundle,
				},
				bytes: bundleBytes,
			}}
			Expect(bindCarriedRefs(refs, []byte("tarball"), pkgRoot, tb, nil, nil, attState)).To(Succeed())
			Expect(attState.CarriedBindings).To(HaveLen(1))
			b := attState.CarriedBindings[0]
			Expect(b.Tier).To(Equal(schema.CarriedTierVerifiedOffline))
			Expect(b.CertificateIdentity).NotTo(BeEmpty())
			Expect(b.CertificateIssuer).NotTo(BeEmpty())
		})

		It("fails closed to verified-transport-only when the mirrored root is the wrong CA (kernel reached, kernel rejects)", func() {
			bundleBytes := readFixture("bindable-bundle.json")
			content := readFixture("bindable-content.bin")
			// unrelated-root.json is a DIFFERENT CA over the same validity window, so
			// SigstoreRootAt selects it and the kernel genuinely runs — but it never
			// signed this bundle, so verification fails. This is the innermost
			// verdict.Verified gate a nil bundle can never exercise.
			var unrelatedRoot schema.SigstoreRoot
			Expect(json.Unmarshal(readFixture("unrelated-root.json"), &unrelatedRoot)).To(Succeed())

			pkgRoot := writeExtracted(map[string][]byte{"bin/app": content})
			tb := trust.NewBundleForTesting(nil, []schema.SigstoreRoot{unrelatedRoot})
			attState := &schema.AttestationState{Status: "verified", PolicyAtInstall: "warn"}
			refs := []carriedRef{{
				ref: schema.AttestationRef{
					Kind:     schema.KindCarriedOpaque,
					Artifact: "pool/sig.att.json",
					Format:   schema.FormatSigstoreBundle,
				},
				bytes: bundleBytes,
			}}
			Expect(bindCarriedRefs(refs, []byte("tarball"), pkgRoot, tb, nil, nil, attState)).To(Succeed())
			Expect(attState.CarriedBindings).To(HaveLen(1))
			b := attState.CarriedBindings[0]
			Expect(b.Tier).To(Equal(schema.CarriedTierVerifiedTransportOnly))
			// No identity may leak from a bundle the kernel rejected.
			Expect(b.CertificateIdentity).To(BeEmpty())
			Expect(b.CertificateIssuer).To(BeEmpty())
		})

		It("falls back to verified-transport-only when the source publishes no sigstore root", func() {
			bundleBytes := readFixture("bindable-bundle.json")
			content := readFixture("bindable-content.bin")

			pkgRoot := writeExtracted(map[string][]byte{"bin/app": content})
			attState := &schema.AttestationState{Status: "verified", PolicyAtInstall: "warn"}
			refs := []carriedRef{{
				ref: schema.AttestationRef{
					Kind:     schema.KindCarriedOpaque,
					Artifact: "pool/sig.att.json",
					Format:   schema.FormatSigstoreBundle,
				},
				bytes: bundleBytes,
			}}
			// nil bundle: no mirrored root, so the kernel is never reached and the
			// binding fails closed to transport-only.
			Expect(bindCarriedRefs(refs, []byte("tarball"), pkgRoot, nil, nil, nil, attState)).To(Succeed())
			Expect(attState.CarriedBindings).To(HaveLen(1))
			Expect(attState.CarriedBindings[0].Tier).To(Equal(schema.CarriedTierVerifiedTransportOnly))
		})

		It("pin present + mirrored absent: verifies offline against the pin", func() {
			bundleBytes := readFixture("bindable-bundle.json")
			content := readFixture("bindable-content.bin")
			var pin schema.SigstoreRoot
			Expect(json.Unmarshal(readFixture("bindable-root.json"), &pin)).To(Succeed())

			pkgRoot := writeExtracted(map[string][]byte{"bin/app": content})
			attState := &schema.AttestationState{Status: "verified", PolicyAtInstall: "warn"}
			refs := []carriedRef{{
				ref: schema.AttestationRef{
					Kind:     schema.KindCarriedOpaque,
					Artifact: "pool/sig.att.json",
					Format:   schema.FormatSigstoreBundle,
				},
				bytes: bundleBytes,
			}}
			// nil bundle (no mirrored root at all) yet the pin verifies: the pin path
			// is independent of the mirror chain.
			Expect(bindCarriedRefs(refs, []byte("tarball"), pkgRoot, nil, &pin, nil, attState)).To(Succeed())
			Expect(attState.CarriedBindings).To(HaveLen(1))
			b := attState.CarriedBindings[0]
			Expect(b.Tier).To(Equal(schema.CarriedTierVerifiedOffline))
			Expect(b.CertificateIdentity).NotTo(BeEmpty())
			Expect(b.CertificateIssuer).NotTo(BeEmpty())
		})

		It("pin is the WRONG CA while the mirror has the RIGHT one: fails closed, mirror NOT consulted (G1)", func() {
			bundleBytes := readFixture("bindable-bundle.json")
			content := readFixture("bindable-content.bin")
			// Mirror carries the correct root A (would verify); the consumer pins the
			// unrelated root B. If the pin is authoritative, the mirrored A is ignored
			// and verification fails => transport-only. A regression that consulted the
			// mirror would flip this to verified-offline — the headline anti-degradation
			// assertion.
			var correctMirror schema.SigstoreRoot
			Expect(json.Unmarshal(readFixture("bindable-root.json"), &correctMirror)).To(Succeed())
			var wrongPin schema.SigstoreRoot
			Expect(json.Unmarshal(readFixture("unrelated-root.json"), &wrongPin)).To(Succeed())

			pkgRoot := writeExtracted(map[string][]byte{"bin/app": content})
			tb := trust.NewBundleForTesting(nil, []schema.SigstoreRoot{correctMirror})
			attState := &schema.AttestationState{Status: "verified", PolicyAtInstall: "warn"}
			refs := []carriedRef{{
				ref: schema.AttestationRef{
					Kind:     schema.KindCarriedOpaque,
					Artifact: "pool/sig.att.json",
					Format:   schema.FormatSigstoreBundle,
				},
				bytes: bundleBytes,
			}}
			Expect(bindCarriedRefs(refs, []byte("tarball"), pkgRoot, tb, &wrongPin, nil, attState)).To(Succeed())
			Expect(attState.CarriedBindings).To(HaveLen(1))
			b := attState.CarriedBindings[0]
			Expect(b.Tier).To(Equal(schema.CarriedTierVerifiedTransportOnly))
			Expect(b.CertificateIdentity).To(BeEmpty())
			Expect(b.CertificateIssuer).To(BeEmpty())
		})

		It("pin is the RIGHT CA while the mirror is DEGRADED: pin bypasses the compromised mirror", func() {
			bundleBytes := readFixture("bindable-bundle.json")
			content := readFixture("bindable-content.bin")
			// A compromised mirror serves the wrong root B; the consumer pins the
			// correct root A. The pin restores verified-offline the mirror could not.
			var degradedMirror schema.SigstoreRoot
			Expect(json.Unmarshal(readFixture("unrelated-root.json"), &degradedMirror)).To(Succeed())
			var correctPin schema.SigstoreRoot
			Expect(json.Unmarshal(readFixture("bindable-root.json"), &correctPin)).To(Succeed())

			pkgRoot := writeExtracted(map[string][]byte{"bin/app": content})
			tb := trust.NewBundleForTesting(nil, []schema.SigstoreRoot{degradedMirror})
			attState := &schema.AttestationState{Status: "verified", PolicyAtInstall: "warn"}
			refs := []carriedRef{{
				ref: schema.AttestationRef{
					Kind:     schema.KindCarriedOpaque,
					Artifact: "pool/sig.att.json",
					Format:   schema.FormatSigstoreBundle,
				},
				bytes: bundleBytes,
			}}
			Expect(bindCarriedRefs(refs, []byte("tarball"), pkgRoot, tb, &correctPin, nil, attState)).To(Succeed())
			Expect(attState.CarriedBindings).To(HaveLen(1))
			Expect(attState.CarriedBindings[0].Tier).To(Equal(schema.CarriedTierVerifiedOffline))
		})

		It("pin whose window excludes the bundle's integrated time: not selected, fails closed", func() {
			bundleBytes := readFixture("bindable-bundle.json")
			content := readFixture("bindable-content.bin")
			// Correct CA bytes, but a validity window that cannot contain the bundle's
			// Rekor integrated time (info.BuildTime). The pin is window-checked exactly
			// like the mirrored path, so it is not selected => transport-only.
			var pin schema.SigstoreRoot
			Expect(json.Unmarshal(readFixture("bindable-root.json"), &pin)).To(Succeed())
			pin.ValidFrom = "2000-01-01T00:00:00Z"
			pin.ValidUntil = "2000-01-02T00:00:00Z"

			pkgRoot := writeExtracted(map[string][]byte{"bin/app": content})
			attState := &schema.AttestationState{Status: "verified", PolicyAtInstall: "warn"}
			refs := []carriedRef{{
				ref: schema.AttestationRef{
					Kind:     schema.KindCarriedOpaque,
					Artifact: "pool/sig.att.json",
					Format:   schema.FormatSigstoreBundle,
				},
				bytes: bundleBytes,
			}}
			Expect(bindCarriedRefs(refs, []byte("tarball"), pkgRoot, nil, &pin, nil, attState)).To(Succeed())
			Expect(attState.CarriedBindings).To(HaveLen(1))
			Expect(attState.CarriedBindings[0].Tier).To(Equal(schema.CarriedTierVerifiedTransportOnly))
		})

		It("out-of-window pin does NOT fall back to a present correct mirror (fails closed)", func() {
			bundleBytes := readFixture("bindable-bundle.json")
			content := readFixture("bindable-content.bin")
			// The mirror carries the correct in-window root A (would verify on its own),
			// but the consumer pins root A with a window that excludes the bundle's
			// integrated time. A set-but-unusable pin must NOT fall back to the mirror —
			// that fallback would reopen the D-4 G1 asymmetry. Fails closed.
			var correctMirror schema.SigstoreRoot
			Expect(json.Unmarshal(readFixture("bindable-root.json"), &correctMirror)).To(Succeed())
			var pin schema.SigstoreRoot
			Expect(json.Unmarshal(readFixture("bindable-root.json"), &pin)).To(Succeed())
			pin.ValidFrom = "2000-01-01T00:00:00Z"
			pin.ValidUntil = "2000-01-02T00:00:00Z"

			pkgRoot := writeExtracted(map[string][]byte{"bin/app": content})
			tb := trust.NewBundleForTesting(nil, []schema.SigstoreRoot{correctMirror})
			attState := &schema.AttestationState{Status: "verified", PolicyAtInstall: "warn"}
			refs := []carriedRef{{
				ref: schema.AttestationRef{
					Kind:     schema.KindCarriedOpaque,
					Artifact: "pool/sig.att.json",
					Format:   schema.FormatSigstoreBundle,
				},
				bytes: bundleBytes,
			}}
			Expect(bindCarriedRefs(refs, []byte("tarball"), pkgRoot, tb, &pin, nil, attState)).To(Succeed())
			Expect(attState.CarriedBindings).To(HaveLen(1))
			b := attState.CarriedBindings[0]
			Expect(b.Tier).To(Equal(schema.CarriedTierVerifiedTransportOnly))
			Expect(b.CertificateIdentity).To(BeEmpty())
			Expect(b.CertificateIssuer).To(BeEmpty())
		})
	})
})
