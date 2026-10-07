package gen_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/tests/e2e/provenancegen/gen"
)

func TestMintSLSAVerifiesUnderBuilderKey(t *testing.T) {
	k := gen.Keys()
	sum := sha256.Sum256(gen.BaseContent)
	env := gen.MintSLSA("bin/app", hex.EncodeToString(sum[:]), gen.BuilderCurrentID, k.BuilderCurrent)

	lookup := func(id string) (ed25519.PublicKey, bool) {
		if id == gen.BuilderCurrentID {
			return k.BuilderCurrent.Public().(ed25519.PublicKey), true
		}
		return nil, false
	}
	tier, keyID, err := attest.VerifyBuilderSignature(env, lookup, func(string) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	if tier != attest.BuilderSigVerified || keyID != gen.BuilderCurrentID {
		t.Fatalf("tier=%v keyID=%q, want verified/%s", tier, keyID, gen.BuilderCurrentID)
	}
}

// TestBuildGenuineIsBuilderVerified proves BuildGenuine mints a real signed
// served repo whose carried SLSA attestation the consumer planner records as
// builder-verified — the positive fixture the acceptance matrix installs
// against (the "genuine" row).
func TestBuildGenuineIsBuilderVerified(t *testing.T) {
	dir := t.TempDir()
	tree, err := gen.BuildGenuine(dir)
	if err != nil {
		t.Fatal(err)
	}

	att := gen.PlanForTest(t, tree, gen.PlanPolicy{Require: []string{gen.SLSAPredicate}, AllowKeys: []string{tree.AllowKeyB64}})
	b := att.CarriedBindings
	if len(b) != 1 || b[0].Tier != schema.CarriedTierBuilderVerified || b[0].VerifyingKeyID != gen.BuilderCurrentID {
		t.Fatalf("carried bindings = %+v, want one builder-verified/%s", b, gen.BuilderCurrentID)
	}
	if b[0].PredicateType != gen.SLSAPredicate {
		t.Fatalf("carried binding predicate type = %q, want %q", b[0].PredicateType, gen.SLSAPredicate)
	}

	// An empty allow-list trusts the source's anchored-bundle key governance
	// and still installs (a weaker posture, not a refusal).
	gen.PlanForTest(t, tree, gen.PlanPolicy{Require: []string{gen.SLSAPredicate}})
}

// TestG1RogueBuilderRefusedByAllowList proves the G1 defense: a
// publisher-minted builder key that IS registered in the (anchor-signed) trust
// bundle — so it genuinely resolves to builder-verified TIER — is still refused
// by planner.Plan when the consumer's NON-EMPTY builders.allow does not name
// that key. The allow-list is the independent anchor a malicious publisher
// cannot forge by minting keys and self-registering them.
func TestG1RogueBuilderRefusedByAllowList(t *testing.T) {
	dir := t.TempDir()
	tree, err := gen.BuildG1Rogue(dir)
	if err != nil {
		t.Fatal(err)
	}
	genKeys := gen.Keys()

	// Positive control: with the rogue key itself allow-listed, the binding
	// must genuinely reach builder-verified under builder-rogue's key id. This
	// proves the refusal asserted below is attributable to the allow-list
	// check, not to a degraded (e.g. transport-only) tier that would also be
	// refused for an unrelated reason and mask a regression in bundle
	// registration.
	rogueKey := gen.PubB64(genKeys.BuilderRogue)
	att := gen.PlanForTest(t, tree, gen.PlanPolicy{Require: []string{gen.SLSAPredicate}, AllowKeys: []string{rogueKey}})
	if len(att.CarriedBindings) != 1 ||
		att.CarriedBindings[0].Tier != schema.CarriedTierBuilderVerified ||
		att.CarriedBindings[0].VerifyingKeyID != gen.BuilderRogueID {
		t.Fatalf("rogue tree must reach builder-verified/%s before the allow-list refuses it; got %+v", gen.BuilderRogueID, att.CarriedBindings)
	}

	// Consumer requires SLSA and allows ONLY builder-current; the fixture is
	// signed by builder-rogue (in the bundle, so builder-verified TIER, but
	// NOT allow-listed) => Plan must REFUSE.
	allowCurrent := gen.PubB64(genKeys.BuilderCurrent)
	err = gen.PlanForTestErr(tree, gen.PlanPolicy{Require: []string{gen.SLSAPredicate}, AllowKeys: []string{allowCurrent}})
	if err == nil {
		t.Fatal("expected Plan to refuse a rogue builder key not in the allow-list")
	}
	if !strings.Contains(err.Error(), "provpkg") {
		t.Fatalf("refusal error = %q, want it to name the package %q", err.Error(), "provpkg")
	}
}

// TestG2StripSLSARefusedUnderRequire proves the G2 defense: a malicious mirror
// strips the carried SLSA attestation from a repo that HAD it (the native SARIF
// ref is left intact) and re-signs the index under the same anchor key. A
// consumer that requires the SLSA predicate must REFUSE (the required predicate
// is genuinely absent, not merely unverified). The control assertion proves the
// strip produced a valid, installable, re-signed index — not a broken one — so
// the refusal above is attributable to the require gate and nothing else.
func TestG2StripSLSARefusedUnderRequire(t *testing.T) {
	dir := t.TempDir()
	tree, err := gen.BuildG2StripSLSA(dir)
	if err != nil {
		t.Fatal(err)
	}
	// SLSA stripped; consumer requires it => refuse.
	if err := gen.PlanForTestErr(tree, gen.PlanPolicy{Require: []string{gen.SLSAPredicate}}); err == nil {
		t.Fatal("expected refusal: required SLSA predicate was stripped")
	}
	// Control: WITHOUT require, the (SARIF-only) package still installs — proves
	// the strip produced a valid, re-signed, installable index (not a broken one).
	if att := gen.PlanForTest(t, tree, gen.PlanPolicy{}); att == nil {
		t.Fatal("expected the stripped repo to still install without require")
	}
}

// TestG5RelabelBindsByDigestNotAdvisoryLabel proves the G5 relabel defense: a
// carried SLSA attestation whose advisory subject name lies ("bin/app") but
// whose digest actually matches a DIFFERENT packed file (bin/other) is bound BY
// DIGEST, not by the advisory label — both at publish time (repo build accepts
// it without tampering, since the digest genuinely matches something packed)
// and at install time, where the consumer's recorded carried binding names the
// REAL bound scope, content:bin/other, never the misleading advisory name
// bin/app.
func TestG5RelabelBindsByDigestNotAdvisoryLabel(t *testing.T) {
	dir := t.TempDir()
	tree, err := gen.BuildG5Relabel(dir)
	if err != nil {
		t.Fatal(err)
	}

	att := gen.PlanForTest(t, tree, gen.PlanPolicy{})
	b := att.CarriedBindings
	if len(b) != 1 {
		t.Fatalf("carried bindings = %+v, want 1", b)
	}
	if b[0].SubjectScope != "content:bin/other" {
		t.Fatalf("carried binding subject scope = %q, want %q (digest-bound, not the misleading advisory name bin/app)", b[0].SubjectScope, "content:bin/other")
	}
}

// TestG5MismatchRefused proves the G5 mismatch defense: a carried SLSA
// attestation whose subject digest matches NO packed file is refused at install
// time by the digest re-bind (internal/planner/planner.go's bindCarriedRefs) —
// not by a broken transport signature or a content-hash error.
// BuildG5Mismatch's swapPoolBlob re-signs the swapped blob's transport
// signature, so the refusal asserted below is attributable only to the binding
// check itself.
func TestG5MismatchRefused(t *testing.T) {
	dir := t.TempDir()
	tree, err := gen.BuildG5Mismatch(dir)
	if err != nil {
		t.Fatal(err)
	}

	err = gen.PlanForTestErr(tree, gen.PlanPolicy{})
	if err == nil {
		t.Fatal("expected refusal: carried SLSA subject digest matches no packed file")
	}
	if !strings.Contains(err.Error(), "does not bind the installed bytes") {
		t.Fatalf("refusal error = %q, want the digest-binding failure (not a transport-signature or content-hash error)", err.Error())
	}
	if !strings.Contains(err.Error(), "binds nothing: no subject digest matches any target") {
		t.Fatalf("refusal error = %q, want the binds-nothing digest mismatch reason", err.Error())
	}
}

// TestG9PredicateMismatchRefused proves the G9 defense: the index ref for the
// carried SLSA attestation positively claims a predicate_type that disagrees
// with the signed payload's authoritative predicateType. This is
// tampering-class, not a missing-predicate gap: the consumer's bindCarriedRefs
// cross-check (internal/planner/planner.go) hard refuses the install under the
// DEFAULT policy — no require and no builders.allow needed, unlike G1/G2's
// require-gated refusals.
func TestG9PredicateMismatchRefused(t *testing.T) {
	dir := t.TempDir()
	tree, err := gen.BuildG9PredicateMismatch(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Index ref claims a different predicate than the signed SLSA payload ⇒
	// tampering-class hard refusal under the DEFAULT policy (no require).
	err = gen.PlanForTestErr(tree, gen.PlanPolicy{})
	if err == nil {
		t.Fatal("expected G9 hard refusal: index predicate_type disagrees with signed payload")
	}
	if !strings.Contains(err.Error(), "predicate type mismatch") {
		t.Fatalf("refusal error = %q, want it to name the predicate type mismatch", err.Error())
	}
	if !strings.Contains(err.Error(), gen.SLSAPredicate) {
		t.Fatalf("refusal error = %q, want it to name the signed payload's predicate type %q", err.Error(), gen.SLSAPredicate)
	}
}

// TestG10DupKeysRefusedUnderRequire proves the G10 defense (see
// internal/attest/dsse.go): a carried SLSA envelope whose JSON is
// byte-identical to a genuine, builder-signed attestation except for a
// spliced-in duplicate top-level "payloadType" key is a parser-differential
// vector polypkg refuses to guess through (attest.VerifyBuilderSignature's
// rejectDuplicateKeys). The planner's install-time cross-check
// (bindCarriedRefs, internal/planner/planner.go) treats that
// structural-invalidity error the same as an unverifiable signature and fails
// the binding CLOSED to verified-transport-only rather than hard-erroring
// itself — refusing an install on a weak tier is a separate policy decision
// (the source's attestation gate). So, like G1/G2, the duplicate-key envelope
// alone does not refuse a DEFAULT (unrequired) install; a source that REQUIRES
// the SLSA predicate does refuse, because verified-transport-only is not an
// anchored tier the require gate accepts. The control assertions below prove
// the refusal is attributable to the duplicate-key downgrade and nothing else:
// without require the tree still installs, and the installed binding records
// verified-transport-only with NO verifying key id — proving the duplicate key
// defeated builder-signature verification specifically, not the digest binding
// (which would refuse outright, like G5 mismatch) or the transport signature
// (swapPoolBlob re-signs it).
func TestG10DupKeysRefusedUnderRequire(t *testing.T) {
	dir := t.TempDir()
	tree, err := gen.BuildG10DupKeys(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Control: WITHOUT require, the duplicate-key envelope still installs, at
	// a downgraded tier — proving the tamper is isolated to defeating
	// builder-signature verification.
	att := gen.PlanForTest(t, tree, gen.PlanPolicy{})
	b := att.CarriedBindings
	if len(b) != 1 {
		t.Fatalf("carried bindings = %+v, want 1", b)
	}
	if b[0].Tier != schema.CarriedTierVerifiedTransportOnly {
		t.Fatalf("carried binding tier = %q, want %q (duplicate key must defeat builder-signature verification, not the digest binding or transport signature)", b[0].Tier, schema.CarriedTierVerifiedTransportOnly)
	}
	if b[0].VerifyingKeyID != "" {
		t.Fatalf("carried binding verifying key id = %q, want empty (a structurally-invalid envelope must not resolve a signer)", b[0].VerifyingKeyID)
	}

	// A consumer that REQUIRES the SLSA predicate must refuse: the degraded
	// tier is not anchored, so the require gate cannot be satisfied.
	err = gen.PlanForTestErr(tree, gen.PlanPolicy{Require: []string{gen.SLSAPredicate}})
	if err == nil {
		t.Fatal("expected G10 refusal under require: duplicate-key envelope cannot reach an anchored tier")
	}
	if !strings.Contains(err.Error(), "attestation policy: required predicate") {
		t.Fatalf("refusal error = %q, want the require-gate refusal naming the missing anchored predicate", err.Error())
	}
	if !strings.Contains(err.Error(), "is not present and verified at an anchored tier from an allowed builder") {
		t.Fatalf("refusal error = %q, want the require-gate's anchored-tier refusal reason", err.Error())
	}
}

// TestG4DigestsTriggerTheirBindingBranch proves each G4 refusal fixture's
// subject digest hits the SPECIFIC internal/attest/binding.go branch it is
// meant to (mismatch / forbidden-weak / no-floor), so the three refusals —
// which surface the same "binds nothing" message end-to-end — are genuinely
// distinct tampers and not accidentally identical.
func TestG4DigestsTriggerTheirBindingBranch(t *testing.T) {
	if err := attest.MatchSubjectDigests(gen.BaseContent, gen.G4MismatchDigest(), "sha256"); err == nil || !strings.Contains(err.Error(), "sha512 digest mismatch") {
		t.Fatalf("G4MismatchDigest: want a sha512 mismatch rejection, got %v", err)
	}
	if err := attest.MatchSubjectDigests(gen.BaseContent, gen.G4Sha1OnlyDigest(), "sha256"); err == nil || !strings.Contains(err.Error(), "forbidden weak digest algorithm") {
		t.Fatalf("G4Sha1OnlyDigest: want a forbidden-weak-algorithm rejection, got %v", err)
	}
	if err := attest.MatchSubjectDigests(gen.BaseContent, gen.G4NoOverlapDigest(), "sha256"); err == nil || !strings.Contains(err.Error(), "no digest at or above floor") {
		t.Fatalf("G4NoOverlapDigest: want a no-floor rejection, got %v", err)
	}
}

// TestG4MultiAlgoInstallsBuilderVerified proves the G4 positive/selection half
// ("all-overlap-must-agree"): a carried SLSA subject offering sha256 AND sha512
// that BOTH match the installed bytes binds and installs builder-verified — the
// multi-algo agreement path does not spuriously fail closed.
func TestG4MultiAlgoInstallsBuilderVerified(t *testing.T) {
	dir := t.TempDir()
	tree, err := gen.BuildG4MultiAlgo(dir)
	if err != nil {
		t.Fatal(err)
	}
	att := gen.PlanForTest(t, tree, gen.PlanPolicy{Require: []string{gen.SLSAPredicate}, AllowKeys: []string{tree.AllowKeyB64}})
	b := att.CarriedBindings
	if len(b) != 1 || b[0].Tier != schema.CarriedTierBuilderVerified || b[0].VerifyingKeyID != gen.BuilderCurrentID {
		t.Fatalf("carried bindings = %+v, want one builder-verified/%s (sha256+sha512 both agree)", b, gen.BuilderCurrentID)
	}
}

// TestG4MismatchAlgoRefused proves the G4 refusal: a carried SLSA subject whose
// sha256 matches the installed bytes but whose sha512 is the hash of DIFFERENT
// bytes is refused at install by the digest re-bind (bindCarriedRefs) under the
// DEFAULT policy — MatchSubjectDigests rejects the sha512 disagreement, so no
// subject binds. buildSwappedSLSA re-signs the swapped blob's transport
// signature, so the refusal is the binding, not a transport error.
func TestG4MismatchAlgoRefused(t *testing.T) {
	dir := t.TempDir()
	tree, err := gen.BuildG4MismatchAlgo(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = gen.PlanForTestErr(tree, gen.PlanPolicy{})
	if err == nil {
		t.Fatal("expected refusal: carried SLSA sha512 disagrees with the installed bytes")
	}
	if !strings.Contains(err.Error(), "does not bind the installed bytes") {
		t.Fatalf("refusal error = %q, want the digest-binding failure (not a transport error)", err.Error())
	}
	if !strings.Contains(err.Error(), "carried attestation binds nothing: no subject digest matches any target") {
		t.Fatalf("refusal error = %q, want the binds-nothing reason", err.Error())
	}
}

// TestG4Sha1OnlyRefused proves the G4 downgrade refusal: a carried SLSA subject
// offering ONLY sha1 — a forbidden weak algorithm — is refused at install by
// the digest re-bind. MatchSubjectDigests rejects sha1 on presence, so no
// subject binds. The refusal is the binding failure, not a transport error
// (buildSwappedSLSA re-signs transport).
func TestG4Sha1OnlyRefused(t *testing.T) {
	dir := t.TempDir()
	tree, err := gen.BuildG4Sha1Only(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = gen.PlanForTestErr(tree, gen.PlanPolicy{})
	if err == nil {
		t.Fatal("expected refusal: carried SLSA offers only the forbidden weak sha1")
	}
	if !strings.Contains(err.Error(), "does not bind the installed bytes") {
		t.Fatalf("refusal error = %q, want the digest-binding failure (not a transport error)", err.Error())
	}
	if !strings.Contains(err.Error(), "carried attestation binds nothing: no subject digest matches any target") {
		t.Fatalf("refusal error = %q, want the binds-nothing reason", err.Error())
	}
}

// TestG4NoOverlapRefused proves the G4 no-overlap refusal: a carried SLSA
// subject offering ONLY an algorithm polypkg cannot recompute (sha3-512) has
// nothing at or above the sha256 floor, so it is unbindable and refused at
// install by the digest re-bind under the DEFAULT policy.
func TestG4NoOverlapRefused(t *testing.T) {
	dir := t.TempDir()
	tree, err := gen.BuildG4NoOverlap(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = gen.PlanForTestErr(tree, gen.PlanPolicy{})
	if err == nil {
		t.Fatal("expected refusal: carried SLSA offers no digest polypkg can verify at the floor")
	}
	if !strings.Contains(err.Error(), "does not bind the installed bytes") {
		t.Fatalf("refusal error = %q, want the digest-binding failure (not a transport error)", err.Error())
	}
	if !strings.Contains(err.Error(), "carried attestation binds nothing: no subject digest matches any target") {
		t.Fatalf("refusal error = %q, want the binds-nothing reason", err.Error())
	}
}

// TestG7PostPublishSubstitutionRefused proves the G7 consumer-side defense
// (two-point binding, install half): an attacker holding the publisher/anchor
// key publishes a genuine tree, then substitutes the packed content/bin/app
// bytes, re-packs the artifact tarball, recomputes its blake3, re-signs the
// artifact transport signature, STRIPS the anchor-signed native
// artifact-binding attestations (SARIF + polypkg-link — which the attacker can
// forge or remove), retargets the index's package artifact ref, and re-signs
// the index — so the artifact transport signature and index content-hash BOTH
// still verify. The builder-signed carried SLSA (subject minted over the
// ORIGINAL bytes) cannot be forged and remains, so the consumer's install-time
// re-bind (bindCarriedRefs) re-derives its subject digest against the
// actually-extracted substituted bytes, matches nothing, and hard refuses under
// the DEFAULT policy. The specificity of the "does not bind the installed
// bytes" message is the transport-verified control: that error is only
// reachable AFTER verifyArtifact (transport signature + content hash) succeeds.
// The final assertion is the layer control: it proves the refusal is the
// CARRIED re-bind, not the native artifact-binding (which the strip removed)
// that would otherwise fire first.
func TestG7PostPublishSubstitutionRefused(t *testing.T) {
	dir := t.TempDir()
	tree, err := gen.BuildG7InstallRefused(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = gen.PlanForTestErr(tree, gen.PlanPolicy{})
	if err == nil {
		t.Fatal("expected refusal: packed content was substituted after publish, carried SLSA subject no longer binds")
	}
	if !strings.Contains(err.Error(), "does not bind the installed bytes") {
		t.Fatalf("refusal error = %q, want the install-time digest re-bind failure (not a transport-signature or content-hash error)", err.Error())
	}
	if !strings.Contains(err.Error(), "carried attestation binds nothing: no subject digest matches any target") {
		t.Fatalf("refusal error = %q, want the binds-nothing reason", err.Error())
	}
	if strings.Contains(err.Error(), "attestation subject digest does not match artifact") {
		t.Fatalf("refusal error = %q, want the CARRIED re-bind, not the native artifact-binding (the strip must remove all native refs)", err.Error())
	}
}

// TestG7PrePackContentRefusedAtBuild proves the G7 producer-side defense
// (two-point binding, pack half): when a repo tries to publish a carried SLSA
// attestation whose subject digest covers bytes DIFFERENT from the
// content/bin/app it actually packs, repo build's pack-time bindCarried
// (internal/repo/carried.go) re-derives the packed artifact/content digests and
// refuses to publish an attestation that binds nothing it packed. Nothing is
// served, so this half has no venom row — it is a Go-only build-error
// assertion, the mirror image of TestG7PostPublishSubstitutionRefused's
// install-time refusal.
func TestG7PrePackContentRefusedAtBuild(t *testing.T) {
	dir := t.TempDir()
	err := gen.BuildG7PackRefusedErr(dir)
	if err == nil {
		t.Fatal("expected a pack-time build error: carried SLSA subject covers bytes the repo does not pack")
	}
	if !strings.Contains(err.Error(), "binds nothing polypkg packed") {
		t.Fatalf("build error = %q, want the pack-time bindCarried refusal (not some other build failure)", err.Error())
	}
}

// Fulcio identity the committed bindable-bundle.json certifies (see
// internal/attest/testdata/sigstoregen/main.go). A verified-offline binding
// records these; the genuine G6 fixture must surface them.
const (
	g6CertIdentity = "https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v1"
	g6CertIssuer   = "https://token.actions.githubusercontent.com"
)

// TestG6SigstoreGenuineVerifiedOffline proves the G6 positive control: a
// genuine offline sigstore bundle carried as attestations/sigstore.json, whose
// SigstoreRoot is published in the served trust bundle, verifies offline
// (inclusion proof + Fulcio chain + Rekor key all present) and binds at
// CarriedTierVerifiedOffline with the recorded Fulcio SAN and issuer — and
// installs under require:[SLSA] because verified-offline is an anchored tier.
// The Format assertion proves it reached the sigstore tier path (not the
// DSSE/builder path).
func TestG6SigstoreGenuineVerifiedOffline(t *testing.T) {
	dir := t.TempDir()
	tree, err := gen.BuildG6SigstoreGenuine(dir)
	if err != nil {
		t.Fatal(err)
	}
	att := gen.PlanForTest(t, tree, gen.PlanPolicy{Require: []string{gen.SLSAPredicate}})
	b := att.CarriedBindings
	if len(b) != 1 {
		t.Fatalf("carried bindings = %+v, want 1", b)
	}
	if b[0].Format != schema.FormatSigstoreBundle {
		t.Fatalf("carried binding format = %q, want %q", b[0].Format, schema.FormatSigstoreBundle)
	}
	if b[0].Tier != schema.CarriedTierVerifiedOffline {
		t.Fatalf("carried binding tier = %q, want %q", b[0].Tier, schema.CarriedTierVerifiedOffline)
	}
	if b[0].CertificateIdentity != g6CertIdentity || b[0].CertificateIssuer != g6CertIssuer {
		t.Fatalf("recorded identity = %q / %q, want %q / %q", b[0].CertificateIdentity, b[0].CertificateIssuer, g6CertIdentity, g6CertIssuer)
	}
	if b[0].PredicateType != gen.SLSAPredicate {
		t.Fatalf("carried binding predicate type = %q, want %q", b[0].PredicateType, gen.SLSAPredicate)
	}
}

// TestG6EmbeddedFixturesMatchCommittedSource guards against silent drift between
// the sigstore fixtures embedded into this generator (gen/testdata/, byte-copied
// for a self-contained go:embed) and their source of truth in
// internal/attest/testdata/. If sigstoregen is re-run and only one location is
// updated, this fails RED instead of letting the G6 rows verify against a stale
// bundle. Runs only under `go test` on the host (where the whole module tree is
// present), never in the container matrix (which runs the generator binary, not
// these tests).
func TestG6EmbeddedFixturesMatchCommittedSource(t *testing.T) {
	for _, name := range []string{"bindable-bundle.json", "bindable-content.bin", "bindable-root.json"} {
		embedded, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatalf("read embedded copy %s: %v", name, err)
		}
		source, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "internal", "attest", "testdata", name))
		if err != nil {
			t.Fatalf("read committed source %s: %v", name, err)
		}
		if !bytes.Equal(embedded, source) {
			t.Fatalf("embedded gen/testdata/%s has drifted from internal/attest/testdata/%s; re-copy after regenerating via sigstoregen", name, name)
		}
	}
}

// TestG6NoInclusionProofDowngradesAndRefuses proves the G6 refusal: a carried
// sigstore bundle whose transparency-log inclusion proof has been stripped can
// no longer be verified offline (sigstore-go's strict bundle parse rejects a
// v0.2+ bundle missing its inclusion proof), so the consumer fails closed to
// CarriedTierVerifiedTransportOnly with NO recorded identity. Under the DEFAULT
// policy it still installs (a downgrade, not a hard refusal); under
// require:[SLSA] it refuses, because verified-transport-only is not an anchored
// tier. The Format assertion proves the stripped bundle still reached the
// sigstore tier path (InspectCarried's lenient probe keeps classifying it
// sigstore-bundle), so the downgrade is the inclusion-proof gate, not a
// reclassification.
func TestG6NoInclusionProofDowngradesAndRefuses(t *testing.T) {
	dir := t.TempDir()
	tree, err := gen.BuildG6NoInclusionProof(dir)
	if err != nil {
		t.Fatal(err)
	}

	// DEFAULT policy: installs at transport-only, no identity recorded.
	att := gen.PlanForTest(t, tree, gen.PlanPolicy{})
	b := att.CarriedBindings
	if len(b) != 1 {
		t.Fatalf("carried bindings = %+v, want 1", b)
	}
	if b[0].Format != schema.FormatSigstoreBundle {
		t.Fatalf("carried binding format = %q, want %q (strip must not reclassify)", b[0].Format, schema.FormatSigstoreBundle)
	}
	if b[0].Tier != schema.CarriedTierVerifiedTransportOnly {
		t.Fatalf("carried binding tier = %q, want %q (stripped inclusion proof must fail closed)", b[0].Tier, schema.CarriedTierVerifiedTransportOnly)
	}
	if b[0].CertificateIdentity != "" || b[0].CertificateIssuer != "" {
		t.Fatalf("recorded identity = %q / %q, want both empty (transport-only records no Fulcio identity)", b[0].CertificateIdentity, b[0].CertificateIssuer)
	}

	// require:[SLSA]: refuses, because verified-transport-only is not anchored.
	err = gen.PlanForTestErr(tree, gen.PlanPolicy{Require: []string{gen.SLSAPredicate}})
	if err == nil {
		t.Fatal("expected refusal under require: a transport-only sigstore binding is not an anchored tier")
	}
	if !strings.Contains(err.Error(), "attestation policy: required predicate") {
		t.Fatalf("refusal error = %q, want the require-gate refusal", err.Error())
	}
	if !strings.Contains(err.Error(), "is not present and verified at an anchored tier from an allowed builder") {
		t.Fatalf("refusal error = %q, want the anchored-tier refusal reason", err.Error())
	}
}

// TestGeneratorAcceptsRelativeOutputDir proves the fixture builders accept a
// RELATIVE output dir. Previously the anchor key was written under dir/.keys and
// its path was recorded relative in the repo manifest; repo build re-resolves
// manifest.Key.Path against the manifest dir (internal/repo/build.go), so a
// relative dir doubled the path ("relout/genuine/relout/genuine/.keys/repo.key")
// and the build failed. Writing the key to an absolute os.MkdirTemp dir fixes it.
// t.Chdir is test-scoped (restored on cleanup) and forbids t.Parallel here.
func TestGeneratorAcceptsRelativeOutputDir(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := gen.BuildGenuine("relout/genuine"); err != nil {
		t.Fatalf("BuildGenuine with a relative output dir must succeed: %v", err)
	}
}
