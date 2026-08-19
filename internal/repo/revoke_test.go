package repo

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jedisct1/go-minisign"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// revBuilder returns a Builder over a fresh test repo. Revoke publishes into the
// manifest's output dir; the repo need not have been built first.
func revBuilder(t *testing.T) *Builder {
	t.Helper()
	mPath, keyDir := newTestRepo(t)
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	return b
}

func TestRevokeAuthorsSignedList(t *testing.T) {
	b := revBuilder(t)
	hash := "blake3:" + strings.Repeat("ab", 32)

	res, err := b.Revoke(RevokeOptions{Attestations: []string{hash}})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if res.Serial != 1 {
		t.Fatalf("first serial = %d, want 1", res.Serial)
	}

	raw, err := os.ReadFile(res.RevocationsPath)
	if err != nil {
		t.Fatalf("read revocations.json: %v", err)
	}
	rl, err := schema.ParseRevocationList(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("emitted list fails schema parse: %v", err)
	}
	if rl.Source != "example" {
		t.Fatalf("source = %q, want example", rl.Source)
	}
	if len(rl.RevokedAttestations) != 1 || rl.RevokedAttestations[0] != hash {
		t.Fatalf("revoked_attestations = %v, want [%s]", rl.RevokedAttestations, hash)
	}
	exp, perr := time.Parse(time.RFC3339, rl.Expires)
	if perr != nil || time.Until(exp) <= 0 {
		t.Fatalf("expires must be a future RFC3339 stamp, got %q", rl.Expires)
	}

	// The detached signature must verify against the repo's own signing key —
	// this is exactly the check the consumer's trust path performs.
	sigRaw, err := os.ReadFile(res.SignaturePath)
	if err != nil {
		t.Fatalf("read .minisig: %v", err)
	}
	pub, err := minisign.DecodePublicKey(b.key.PublicKeyFile("k"))
	if err != nil {
		t.Fatalf("DecodePublicKey: %v", err)
	}
	sig, err := minisign.DecodeSignature(string(sigRaw))
	if err != nil {
		t.Fatalf("DecodeSignature: %v", err)
	}
	ok, verr := pub.Verify(raw, sig)
	if verr != nil || !ok {
		t.Fatalf("signature must verify: ok=%v err=%v", ok, verr)
	}
}

func TestRevokeIsCumulativeAndBumpsSerial(t *testing.T) {
	b := revBuilder(t)
	hash := "blake3:" + strings.Repeat("cd", 32)

	if _, err := b.Revoke(RevokeOptions{Attestations: []string{hash}}); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	res, err := b.Revoke(RevokeOptions{BuilderKeys: []string{"builder-a"}})
	if err != nil {
		t.Fatalf("second Revoke: %v", err)
	}
	if res.Serial != 2 {
		t.Fatalf("second serial = %d, want 2 (monotonic bump)", res.Serial)
	}

	raw, _ := os.ReadFile(res.RevocationsPath)
	rl, err := schema.ParseRevocationList(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// The earlier attestation revocation must survive — revoke never un-revokes.
	if len(rl.RevokedAttestations) != 1 || rl.RevokedAttestations[0] != hash {
		t.Fatalf("cumulative attestations lost: %v", rl.RevokedAttestations)
	}
	if len(rl.RevokedBuilderKeys) != 1 || rl.RevokedBuilderKeys[0] != "builder-a" {
		t.Fatalf("builder key not recorded: %v", rl.RevokedBuilderKeys)
	}
}

func TestRevokeDedupesRepeatedTargets(t *testing.T) {
	b := revBuilder(t)
	hash := "blake3:" + strings.Repeat("ef", 32)

	if _, err := b.Revoke(RevokeOptions{Attestations: []string{hash}}); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	res, err := b.Revoke(RevokeOptions{Attestations: []string{hash, hash}})
	if err != nil {
		t.Fatalf("second Revoke: %v", err)
	}
	raw, _ := os.ReadFile(res.RevocationsPath)
	rl, _ := schema.ParseRevocationList(bytes.NewReader(raw))
	if len(rl.RevokedAttestations) != 1 {
		t.Fatalf("re-revoking the same hash must not duplicate it: %v", rl.RevokedAttestations)
	}
}

// TestRevokeOutputIsHonoredByConsumerVerifier is the producer->consumer
// round-trip: what `repo revoke` publishes must verify and be honored by the
// SAME trust path a client uses to load a revocation list. It proves the bytes
// and signature the producer emits are exactly what the consumer accepts —
// without a hand-rolled harness.
func TestRevokeOutputIsHonoredByConsumerVerifier(t *testing.T) {
	b := revBuilder(t)
	hash := "blake3:" + strings.Repeat("dd", 32)

	res, err := b.Revoke(RevokeOptions{Attestations: []string{hash}, BuilderKeys: []string{"builder-x"}})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	doc, err := os.ReadFile(res.RevocationsPath)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(res.SignaturePath)
	if err != nil {
		t.Fatal(err)
	}

	// Anchor the real consumer verifier to the repo's own signing (trust-root)
	// key — the same key a client pins as trust_root.pub.
	v, err := trust.NewVerifier("polypkg-native", b.key.PublicKeyFile("anchor"), "example")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	revs, serial, _, _, err := v.LoadRevocationList(doc, string(sig), 0, "")
	if err != nil {
		t.Fatalf("consumer rejected repo revoke output: %v", err)
	}
	if serial != res.Serial {
		t.Fatalf("consumer serial %d != producer serial %d", serial, res.Serial)
	}
	if !revs.IsAttestationRevoked(hash) {
		t.Fatalf("consumer does not honor revoked attestation %s", hash)
	}
	if !revs.IsBuilderKeyRevoked("builder-x") {
		t.Fatalf("consumer does not honor revoked builder key builder-x")
	}
}

func TestRevokeRejectsEmptyInput(t *testing.T) {
	b := revBuilder(t)
	if _, err := b.Revoke(RevokeOptions{}); err == nil {
		t.Fatal("Revoke with no attestation or builder key must error")
	}
}

func TestRevokeRejectsInvalidExistingListOnDisk(t *testing.T) {
	b := revBuilder(t)
	outDir := b.insp.layout.outputDir
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A corrupt/unparseable revocations.json must not be silently overwritten —
	// its serial and existing entries would be lost, dropping live revocations.
	if err := os.WriteFile(filepath.Join(outDir, "revocations.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	hash := "blake3:" + strings.Repeat("22", 32)
	if _, err := b.Revoke(RevokeOptions{Attestations: []string{hash}}); err == nil {
		t.Fatal("Revoke must refuse to extend an unparseable revocations.json")
	}
}

func TestRevokeRejectsMalformedAttestationBeforeSigning(t *testing.T) {
	b := revBuilder(t)
	// A non-blake3 attestation value must be rejected by the pre-sign schema
	// round-trip so schema-invalid garbage is never signed or published.
	if _, err := b.Revoke(RevokeOptions{Attestations: []string{"sha256:deadbeef"}}); err == nil {
		t.Fatal("Revoke must reject a non-blake3 attestation value")
	}
	if _, statErr := os.Stat(filepath.Join(b.insp.layout.outputDir, "revocations.json")); statErr == nil {
		t.Fatal("no revocations.json may be written when authoring fails validation")
	}
}

func TestMergedSetsAddRemoveAndChanged(t *testing.T) {
	existing := &schema.RevocationList{
		RevokedAttestations: []string{"blake3:aa", "blake3:bb"},
		RevokedBuilderKeys:  []string{"k1"},
	}
	atts, keys, changed := mergedSets(existing, []string{"blake3:cc"}, nil, nil, nil)
	if !changed || len(atts) != 3 || len(keys) != 1 {
		t.Fatalf("add-new: atts=%v keys=%v changed=%v", atts, keys, changed)
	}
	if _, _, c := mergedSets(existing, []string{"blake3:aa"}, nil, nil, nil); c {
		t.Fatal("re-adding an existing hash must not report changed")
	}
	atts, _, changed = mergedSets(existing, nil, nil, []string{"blake3:aa"}, nil)
	if !changed || len(atts) != 1 || atts[0] != "blake3:bb" {
		t.Fatalf("remove-present: atts=%v changed=%v", atts, changed)
	}
	if _, _, c := mergedSets(existing, nil, nil, []string{"blake3:zz"}, nil); c {
		t.Fatal("removing an absent hash must not report changed")
	}
}

func TestRevokeRejectsForeignSourceOnDisk(t *testing.T) {
	b := revBuilder(t)
	// A pre-existing revocations.json belonging to a different source must not be
	// silently overwritten — that would be clobbering another repo's published set.
	outDir := b.insp.layout.outputDir
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := `{"schema":"polypkg.revocation-list/v1","source":"other","serial":7,"expires":"2099-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(outDir, "revocations.json"), []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}
	hash := "blake3:" + strings.Repeat("11", 32)
	if _, err := b.Revoke(RevokeOptions{Attestations: []string{hash}}); err == nil {
		t.Fatal("Revoke must refuse to overwrite a revocations.json for another source")
	}
}

func TestRevokeRemoveDropsEntryAndBumpsSerial(t *testing.T) {
	b := revBuilder(t)
	h := "blake3:" + strings.Repeat("ab", 32)
	if _, err := b.Revoke(RevokeOptions{Attestations: []string{h}}); err != nil {
		t.Fatalf("seed revoke: %v", err)
	}
	res, err := b.Revoke(RevokeOptions{RemoveAttestations: []string{h}})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if res.Serial != 2 {
		t.Fatalf("serial = %d, want 2", res.Serial)
	}
	if len(res.RevokedAttestations) != 0 {
		t.Fatalf("hash must be dropped, got %v", res.RevokedAttestations)
	}
}

func TestRevokeRemoveAbsentIsNoOpSet(t *testing.T) {
	b := revBuilder(t)
	h := "blake3:" + strings.Repeat("ab", 32)
	if _, err := b.Revoke(RevokeOptions{Attestations: []string{h}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	res, err := b.Revoke(RevokeOptions{RemoveAttestations: []string{"blake3:" + strings.Repeat("cd", 32)}})
	if err != nil {
		t.Fatalf("remove-absent: %v", err)
	}
	if len(res.RevokedAttestations) != 1 || res.RevokedAttestations[0] != h {
		t.Fatalf("removing an absent hash must leave the set intact, got %v", res.RevokedAttestations)
	}
}

func TestRevokeRemoveWithNoListErrors(t *testing.T) {
	b := revBuilder(t)
	if _, err := b.Revoke(RevokeOptions{RemoveAttestations: []string{"blake3:" + strings.Repeat("ab", 32)}}); err == nil {
		t.Fatal("pruning with no published list must error")
	}
}

func TestRevokeRejectsAddRemoveMix(t *testing.T) {
	b := revBuilder(t)
	if _, err := b.Revoke(RevokeOptions{
		Attestations:       []string{"blake3:" + strings.Repeat("ab", 32)},
		RemoveAttestations: []string{"blake3:" + strings.Repeat("cd", 32)},
	}); err == nil {
		t.Fatal("mixing add and remove in one invocation must error")
	}
}

func TestPropagateRevocationsEmitsThenSkipsSteadyState(t *testing.T) {
	b := revBuilder(t)
	h := "blake3:" + strings.Repeat("ab", 32)
	res, emitted, err := b.PropagateRevocations([]string{h}, []string{"builder-a"}, DefaultValidFor)
	if err != nil || !emitted {
		t.Fatalf("first propagate must emit: emitted=%v err=%v", emitted, err)
	}
	if res.Serial != 1 {
		t.Fatalf("serial = %d, want 1", res.Serial)
	}
	_, emitted2, err := b.PropagateRevocations([]string{h}, []string{"builder-a"}, DefaultValidFor)
	if err != nil {
		t.Fatalf("second propagate: %v", err)
	}
	if emitted2 {
		t.Fatal("an unchanged set with a fresh list must not re-emit")
	}
}

func TestPropagateRevocationsRenewsBelowHalfLife(t *testing.T) {
	b := revBuilder(t)
	h := "blake3:" + strings.Repeat("ab", 32)
	if _, _, err := b.PropagateRevocations([]string{h}, nil, time.Nanosecond); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, emitted, err := b.PropagateRevocations([]string{h}, nil, DefaultValidFor)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if !emitted {
		t.Fatal("a list below its freshness half-life must be renewed even if the set is unchanged")
	}
}

func TestPropagateRevocationsNoUpstreamNoExistingIsNoOp(t *testing.T) {
	b := revBuilder(t)
	res, emitted, err := b.PropagateRevocations(nil, nil, DefaultValidFor)
	if err != nil {
		t.Fatalf("PropagateRevocations: %v", err)
	}
	if emitted {
		t.Fatal("no upstream revocations and no existing list must be a no-op, not an empty published list")
	}
	if res.RevocationsPath != "" {
		t.Fatalf("no-op must return a zero result, got path %q", res.RevocationsPath)
	}
	// No revocations.json may have been created.
	if _, statErr := os.Stat(filepath.Join(b.insp.layout.outputDir, "revocations.json")); statErr == nil {
		t.Fatal("no-op must not write a revocations.json")
	}
}

func TestPropagateRevocationsIsCumulativeAcrossCalls(t *testing.T) {
	b := revBuilder(t)
	h1 := "blake3:" + strings.Repeat("ab", 32)
	h2 := "blake3:" + strings.Repeat("cd", 32)
	if _, _, err := b.PropagateRevocations([]string{h1}, nil, DefaultValidFor); err != nil {
		t.Fatalf("first: %v", err)
	}
	res, emitted, err := b.PropagateRevocations([]string{h2}, nil, DefaultValidFor)
	if err != nil || !emitted {
		t.Fatalf("second: emitted=%v err=%v", emitted, err)
	}
	if len(res.RevokedAttestations) != 2 {
		t.Fatalf("cumulative must keep both hashes, got %v", res.RevokedAttestations)
	}
}
