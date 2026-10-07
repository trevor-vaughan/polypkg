package planner

import (
	"errors"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

func TestTierAnchored(t *testing.T) {
	cases := []struct {
		tier string
		want bool
	}{
		{schema.CarriedTierBuilderVerified, true},
		{schema.CarriedTierVerifiedOffline, true},
		{schema.CarriedTierVerifiedTransportOnly, false},
		{schema.CarriedTierBoundUnverified, false},
		{"", false},
	}
	for _, c := range cases {
		if got := tierAnchored(c.tier); got != c.want {
			t.Errorf("tierAnchored(%q) = %v, want %v", c.tier, got, c.want)
		}
	}
}

func TestMatchSAN(t *testing.T) {
	cases := []struct {
		pattern, san string
		want         bool
	}{
		{"https://ex/wf.yml@refs/heads/main", "https://ex/wf.yml@refs/heads/main", true},
		{"https://ex/wf.yml@refs/heads/main", "https://ex/wf.yml@refs/tags/v1", false},
		{"https://ex/wf.yml@*", "https://ex/wf.yml@refs/heads/main", true},
		{"https://ex/wf.yml@*", "https://ex/OTHER.yml@refs/heads/main", false},
		{"https://ex/wf.yml@*", "https://ex/wf.yml@", true},
		{"*", "anything", false},
		{"", "anything", false},
	}
	for _, c := range cases {
		if got := matchSAN(c.pattern, c.san); got != c.want {
			t.Errorf("matchSAN(%q, %q) = %v, want %v", c.pattern, c.san, got, c.want)
		}
	}
}

func TestIdentityAllowed(t *testing.T) {
	pub := "dGVzdC1lZDI1NTE5LXB1YmtleQ==" // base64, opaque for the test
	bundle := trust.NewBundleForTesting([]schema.BuilderKey{
		{KeyID: "k1", PublicKey: pub, Algo: "ed25519", ValidFrom: "2020-01-01T00:00:00Z"},
	}, nil)

	bv := &schema.CarriedBinding{Tier: schema.CarriedTierBuilderVerified, VerifyingKeyID: "k1"}
	vo := &schema.CarriedBinding{
		Tier:                schema.CarriedTierVerifiedOffline,
		CertificateIssuer:   "https://token.actions.githubusercontent.com",
		CertificateIdentity: "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main",
	}
	keyEntry := schema.BuilderAllowEntry{Key: pub}
	sigEntry := schema.BuilderAllowEntry{Sigstore: &schema.SigstoreAllow{
		Issuer: "https://token.actions.githubusercontent.com",
		SAN:    "https://github.com/org/repo/.github/workflows/build.yml@*",
	}}

	if !identityAllowed(bv, nil, bundle) {
		t.Error("empty allow-list must allow any anchored binding")
	}
	if !identityAllowed(bv, []schema.BuilderAllowEntry{keyEntry}, bundle) {
		t.Error("builder-verified should match its key entry")
	}
	if identityAllowed(bv, []schema.BuilderAllowEntry{{Key: "b3RoZXI="}}, bundle) {
		t.Error("builder-verified must not match a different key")
	}
	if identityAllowed(bv, []schema.BuilderAllowEntry{sigEntry}, bundle) {
		t.Error("builder-verified must not match a sigstore entry")
	}
	if !identityAllowed(vo, []schema.BuilderAllowEntry{sigEntry}, bundle) {
		t.Error("verified-offline should match issuer + SAN prefix")
	}
	bad := schema.BuilderAllowEntry{Sigstore: &schema.SigstoreAllow{Issuer: "https://evil", SAN: "https://github.com/org/repo/.github/workflows/build.yml@*"}}
	if identityAllowed(vo, []schema.BuilderAllowEntry{bad}, bundle) {
		t.Error("verified-offline must be refused on issuer mismatch")
	}
	if identityAllowed(vo, []schema.BuilderAllowEntry{keyEntry}, bundle) {
		t.Error("verified-offline must not match a key entry")
	}
	if identityAllowed(bv, []schema.BuilderAllowEntry{keyEntry}, nil) {
		t.Error("nil bundle must refuse a key match (fail closed)")
	}
}

func TestEnforceAttestationPolicy(t *testing.T) {
	const slsa = "https://slsa.dev/provenance/v1"
	pub := "dGVzdC1lZDI1NTE5LXB1YmtleQ=="
	bundle := trust.NewBundleForTesting([]schema.BuilderKey{
		{KeyID: "k1", PublicKey: pub, Algo: "ed25519", ValidFrom: "2020-01-01T00:00:00Z"},
	}, nil)
	keyAllow := &schema.BuilderAllow{Allow: []schema.BuilderAllowEntry{{Key: pub}}}

	stateWith := func(bindings ...schema.CarriedBinding) *schema.AttestationState {
		return &schema.AttestationState{Status: "verified", CarriedBindings: bindings}
	}
	bvSLSA := schema.CarriedBinding{PredicateType: slsa, Tier: schema.CarriedTierBuilderVerified, VerifyingKeyID: "k1"}

	if err := enforceAttestationPolicy(stateWith(bvSLSA), nil, bundle, nil); err != nil {
		t.Errorf("nil policy must be a no-op: %v", err)
	}
	if err := enforceAttestationPolicy(stateWith(), &schema.SourceAttestationPolicy{}, bundle, nil); err != nil {
		t.Errorf("empty require must be a no-op: %v", err)
	}
	pol := &schema.SourceAttestationPolicy{Require: []string{slsa}, Builders: keyAllow}
	if err := enforceAttestationPolicy(stateWith(bvSLSA), pol, bundle, nil); err != nil {
		t.Errorf("require satisfied by builder-verified+allowed key should pass: %v", err)
	}
	badPol := &schema.SourceAttestationPolicy{Require: []string{slsa}, Builders: &schema.BuilderAllow{Allow: []schema.BuilderAllowEntry{{Key: "b3RoZXI="}}}}
	if err := enforceAttestationPolicy(stateWith(bvSLSA), badPol, bundle, nil); err == nil {
		t.Error("G1: builder-verified with a non-allow-listed key must refuse")
	}
	sarifNative := &schema.AttestationState{Status: "verified", PredicateTypes: []string{"https://polypkg.dev/attestation/sarif/v1"}}
	if err := enforceAttestationPolicy(sarifNative, &schema.SourceAttestationPolicy{Require: []string{slsa}}, bundle, nil); err == nil {
		t.Error("G2: require SLSA with only a native SARIF present must refuse")
	}
	transport := schema.CarriedBinding{PredicateType: slsa, Tier: schema.CarriedTierVerifiedTransportOnly}
	if err := enforceAttestationPolicy(stateWith(transport), &schema.SourceAttestationPolicy{Require: []string{slsa}}, bundle, nil); err == nil {
		t.Error("tier: a verified-transport-only binding must not satisfy require")
	}
	vo := schema.CarriedBinding{
		PredicateType: slsa, Tier: schema.CarriedTierVerifiedOffline,
		CertificateIssuer: "https://iss", CertificateIdentity: "https://san/wf.yml@refs/heads/main",
	}
	sigPol := &schema.SourceAttestationPolicy{Require: []string{slsa}, Builders: &schema.BuilderAllow{Allow: []schema.BuilderAllowEntry{{Sigstore: &schema.SigstoreAllow{Issuer: "https://iss", SAN: "https://san/wf.yml@*"}}}}}
	if err := enforceAttestationPolicy(stateWith(vo), sigPol, bundle, nil); err != nil {
		t.Errorf("verified-offline + matching sigstore should pass: %v", err)
	}
	badSig := &schema.SourceAttestationPolicy{Require: []string{slsa}, Builders: &schema.BuilderAllow{Allow: []schema.BuilderAllowEntry{{Sigstore: &schema.SigstoreAllow{Issuer: "https://iss", SAN: "https://OTHER/wf.yml@*"}}}}}
	if err := enforceAttestationPolicy(stateWith(vo), badSig, bundle, nil); err == nil {
		t.Error("verified-offline with a mismatched SAN must refuse")
	}
	if err := enforceAttestationPolicy(stateWith(bvSLSA), &schema.SourceAttestationPolicy{Require: []string{slsa}}, bundle, nil); err != nil {
		t.Errorf("empty allow-list should accept a builder-verified binding: %v", err)
	}
	natState := &schema.AttestationState{Status: "verified", PredicateTypes: []string{slsa}}
	if err := enforceAttestationPolicy(natState, &schema.SourceAttestationPolicy{Require: []string{slsa}}, bundle, nil); err != nil {
		t.Errorf("native predicate should satisfy require with no allow-list: %v", err)
	}
	if err := enforceAttestationPolicy(natState, &schema.SourceAttestationPolicy{Require: []string{slsa}, Builders: keyAllow}, bundle, nil); err == nil {
		t.Error("native predicate must NOT satisfy an identity-pinned require (G1 bypass)")
	}
	if err := enforceAttestationPolicy(nil, &schema.SourceAttestationPolicy{Require: []string{slsa}}, bundle, nil); err == nil {
		t.Error("nil attestation state with a require must refuse")
	}
}

func TestVerifiedPredicateTypes(t *testing.T) {
	if got := verifiedPredicateTypes(nil); got != nil {
		t.Errorf("nil state must yield nil, got %v", got)
	}
	state := &schema.AttestationState{
		PredicateTypes: []string{"native-a"},
		CarriedBindings: []schema.CarriedBinding{
			{PredicateType: "slsa", Tier: schema.CarriedTierBuilderVerified},
			{PredicateType: "offline", Tier: schema.CarriedTierVerifiedOffline},
			{PredicateType: "weak", Tier: schema.CarriedTierVerifiedTransportOnly},
			{PredicateType: "bare", Tier: schema.CarriedTierBoundUnverified},
			{PredicateType: "native-a", Tier: schema.CarriedTierBuilderVerified}, // duplicate of native
		},
	}
	got := verifiedPredicateTypes(state)
	want := map[string]bool{"native-a": true, "slsa": true, "offline": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want keys %v", got, want)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected predicate %q in %v (transport-only/bound-unverified must be excluded)", g, got)
		}
	}
}

func TestEnforcePostureFloor(t *testing.T) {
	const slsa = "https://slsa.dev/provenance/v1"
	anchored := func(pt, tier string) *schema.AttestationState {
		return &schema.AttestationState{CarriedBindings: []schema.CarriedBinding{{PredicateType: pt, Tier: tier}}}
	}
	priorSLSA := anchored(slsa, schema.CarriedTierBuilderVerified)

	if err := enforcePostureFloor(&schema.AttestationState{}, nil, false); err != nil {
		t.Errorf("nil prior must not gate: %v", err)
	}
	if err := enforcePostureFloor(anchored(slsa, schema.CarriedTierBuilderVerified), priorSLSA, false); err != nil {
		t.Errorf("SLSA still anchored should pass: %v", err)
	}
	if err := enforcePostureFloor(anchored(slsa, schema.CarriedTierVerifiedOffline), priorSLSA, false); err != nil {
		t.Errorf("SLSA at a peer anchored tier should pass: %v", err)
	}
	if err := enforcePostureFloor(anchored(slsa, schema.CarriedTierVerifiedTransportOnly), priorSLSA, false); err == nil {
		t.Error("SLSA dropping below an anchored tier must refuse")
	}
	err := enforcePostureFloor(&schema.AttestationState{}, priorSLSA, false)
	if err == nil {
		t.Fatal("a dropped predicate must refuse")
	}
	if !strings.Contains(err.Error(), slsa) || !strings.Contains(err.Error(), "posture floor") {
		t.Errorf("error should name the predicate and the floor: %v", err)
	}
	if err := enforcePostureFloor(&schema.AttestationState{}, priorSLSA, true); err != nil {
		t.Errorf("exact-version pin must accept the drop: %v", err)
	}
	nat := &schema.AttestationState{PredicateTypes: []string{"sarif"}}
	if err := enforcePostureFloor(nat, nat, false); err != nil {
		t.Errorf("native predicate still present should pass: %v", err)
	}
	if err := enforcePostureFloor(&schema.AttestationState{}, nat, false); err == nil {
		t.Error("a dropped native predicate must refuse")
	}
}

// The posture floor is right to refuse a mirror hop that downgrades
// a natively-attested predicate to carried-opaque, but the refusal used to offer
// only "pin the exact version", which permanently waives anti-downgrade for the
// package. When the regression has the shape of a source change — natively
// verified before, merely carried now — the error must say so.
func TestPostureFloorNamesSourceChangeShape(t *testing.T) {
	const sarif = "https://polypkg.dev/attestation/sarif/v1"
	prior := &schema.AttestationState{PredicateTypes: []string{sarif}}
	now := &schema.AttestationState{CarriedBindings: []schema.CarriedBinding{
		{PredicateType: sarif, Tier: schema.CarriedTierBoundUnverified},
	}}

	err := enforcePostureFloor(now, prior, false)
	if err == nil {
		t.Fatal("a natively-verified predicate degraded to carried-opaque must refuse")
	}
	var pfe *PostureFloorError
	if !errors.As(err, &pfe) {
		t.Fatalf("want a *PostureFloorError, got %T: %v", err, err)
	}
	if pfe.Predicate != sarif {
		t.Errorf("Predicate = %q, want %q", pfe.Predicate, sarif)
	}
	if !pfe.NativeBefore {
		t.Error("NativeBefore must be true: the prior generation verified it natively")
	}
	if pfe.CurrentTier != schema.CarriedTierBoundUnverified {
		t.Errorf("CurrentTier = %q, want %q", pfe.CurrentTier, schema.CarriedTierBoundUnverified)
	}
	if !pfe.SourceChangeShaped() {
		t.Error("SourceChangeShaped must be true for native-before / carried-now")
	}
	msg := err.Error()
	if !strings.Contains(msg, sarif) || !strings.Contains(msg, "posture floor") {
		t.Errorf("message must still name the predicate and the floor: %s", msg)
	}
	if !strings.Contains(msg, "natively") || !strings.Contains(msg, schema.CarriedTierBoundUnverified) {
		t.Errorf("message must contrast the native install tier with the current carried tier: %s", msg)
	}
}

// A predicate the current source does not carry at all is a plain regression,
// not a source-change downgrade: the message must not claim otherwise.
func TestPostureFloorPlainRegressionIsNotSourceChangeShaped(t *testing.T) {
	const sarif = "https://polypkg.dev/attestation/sarif/v1"
	prior := &schema.AttestationState{PredicateTypes: []string{sarif}}

	err := enforcePostureFloor(&schema.AttestationState{}, prior, false)
	if err == nil {
		t.Fatal("a dropped predicate must refuse")
	}
	var pfe *PostureFloorError
	if !errors.As(err, &pfe) {
		t.Fatalf("want a *PostureFloorError, got %T: %v", err, err)
	}
	if pfe.CurrentTier != "" {
		t.Errorf("CurrentTier = %q, want empty (the source carries nothing for it)", pfe.CurrentTier)
	}
	if pfe.SourceChangeShaped() {
		t.Error("a wholly absent predicate is not a source-change downgrade")
	}
	if strings.Contains(err.Error(), "natively") {
		t.Errorf("plain regression must not claim a native-to-carried change: %s", err)
	}
}

// A predicate that was anchored-carried before and is weaker-carried now is
// also not a native-to-carried change.
func TestPostureFloorCarriedTierDropIsNotSourceChangeShaped(t *testing.T) {
	const slsa = "https://slsa.dev/provenance/v1"
	prior := &schema.AttestationState{CarriedBindings: []schema.CarriedBinding{
		{PredicateType: slsa, Tier: schema.CarriedTierBuilderVerified},
	}}
	now := &schema.AttestationState{CarriedBindings: []schema.CarriedBinding{
		{PredicateType: slsa, Tier: schema.CarriedTierVerifiedTransportOnly},
	}}
	err := enforcePostureFloor(now, prior, false)
	if err == nil {
		t.Fatal("a carried tier drop must refuse")
	}
	var pfe *PostureFloorError
	if !errors.As(err, &pfe) {
		t.Fatalf("want a *PostureFloorError, got %T: %v", err, err)
	}
	if pfe.NativeBefore {
		t.Error("NativeBefore must be false: the prior tier was carried, not native")
	}
	if pfe.SourceChangeShaped() {
		t.Error("carried-to-carried is not a native-to-carried change")
	}
}

// A revoked builder key used to produce the generic "not present and
// verified" policy error, which tells the operator the predicate is missing when
// it is present, signed, correct — and revoked.
func TestAttestationPolicyErrorNamesRevokedBuilderKey(t *testing.T) {
	const slsa = "https://slsa.dev/provenance/v1"
	pol := &schema.SourceAttestationPolicy{Require: []string{slsa}}
	state := &schema.AttestationState{CarriedBindings: []schema.CarriedBinding{
		{PredicateType: slsa, Tier: schema.CarriedTierVerifiedTransportOnly},
	}}

	err := enforceAttestationPolicy(state, pol, nil, []string{"builder-current"})
	if err == nil {
		t.Fatal("a transport-only binding must not satisfy a require gate")
	}
	var ape *AttestationPolicyError
	if !errors.As(err, &ape) {
		t.Fatalf("want an *AttestationPolicyError, got %T: %v", err, err)
	}
	if ape.Predicate != slsa {
		t.Errorf("Predicate = %q, want %q", ape.Predicate, slsa)
	}
	msg := err.Error()
	if !strings.Contains(msg, "revoke") {
		t.Errorf("message must say the key was revoked: %s", msg)
	}
	if !strings.Contains(msg, "builder-current") {
		t.Errorf("message must name the revoked key id: %s", msg)
	}
}

// With no revoked key in play the message must stay exactly the factual
// "not present and verified" statement — no invented revocation claim.
func TestAttestationPolicyErrorWithoutRevocationIsUnchanged(t *testing.T) {
	const slsa = "https://slsa.dev/provenance/v1"
	pol := &schema.SourceAttestationPolicy{Require: []string{slsa}}

	err := enforceAttestationPolicy(&schema.AttestationState{}, pol, nil, nil)
	if err == nil {
		t.Fatal("an absent predicate must not satisfy a require gate")
	}
	msg := err.Error()
	if !strings.Contains(msg, "is not present and verified at an anchored tier from an allowed builder") {
		t.Errorf("unexpected message: %s", msg)
	}
	if strings.Contains(msg, "revoke") {
		t.Errorf("message must not mention revocation when none applies: %s", msg)
	}
}
