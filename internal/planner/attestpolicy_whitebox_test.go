package planner

import (
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

	if err := enforceAttestationPolicy(stateWith(bvSLSA), nil, bundle); err != nil {
		t.Errorf("nil policy must be a no-op: %v", err)
	}
	if err := enforceAttestationPolicy(stateWith(), &schema.SourceAttestationPolicy{}, bundle); err != nil {
		t.Errorf("empty require must be a no-op: %v", err)
	}
	pol := &schema.SourceAttestationPolicy{Require: []string{slsa}, Builders: keyAllow}
	if err := enforceAttestationPolicy(stateWith(bvSLSA), pol, bundle); err != nil {
		t.Errorf("require satisfied by builder-verified+allowed key should pass: %v", err)
	}
	badPol := &schema.SourceAttestationPolicy{Require: []string{slsa}, Builders: &schema.BuilderAllow{Allow: []schema.BuilderAllowEntry{{Key: "b3RoZXI="}}}}
	if err := enforceAttestationPolicy(stateWith(bvSLSA), badPol, bundle); err == nil {
		t.Error("G1: builder-verified with a non-allow-listed key must refuse")
	}
	sarifNative := &schema.AttestationState{Status: "verified", PredicateTypes: []string{"https://polypkg.dev/attestation/sarif/v1"}}
	if err := enforceAttestationPolicy(sarifNative, &schema.SourceAttestationPolicy{Require: []string{slsa}}, bundle); err == nil {
		t.Error("G2: require SLSA with only a native SARIF present must refuse")
	}
	transport := schema.CarriedBinding{PredicateType: slsa, Tier: schema.CarriedTierVerifiedTransportOnly}
	if err := enforceAttestationPolicy(stateWith(transport), &schema.SourceAttestationPolicy{Require: []string{slsa}}, bundle); err == nil {
		t.Error("tier: a verified-transport-only binding must not satisfy require")
	}
	vo := schema.CarriedBinding{
		PredicateType: slsa, Tier: schema.CarriedTierVerifiedOffline,
		CertificateIssuer: "https://iss", CertificateIdentity: "https://san/wf.yml@refs/heads/main",
	}
	sigPol := &schema.SourceAttestationPolicy{Require: []string{slsa}, Builders: &schema.BuilderAllow{Allow: []schema.BuilderAllowEntry{{Sigstore: &schema.SigstoreAllow{Issuer: "https://iss", SAN: "https://san/wf.yml@*"}}}}}
	if err := enforceAttestationPolicy(stateWith(vo), sigPol, bundle); err != nil {
		t.Errorf("verified-offline + matching sigstore should pass: %v", err)
	}
	badSig := &schema.SourceAttestationPolicy{Require: []string{slsa}, Builders: &schema.BuilderAllow{Allow: []schema.BuilderAllowEntry{{Sigstore: &schema.SigstoreAllow{Issuer: "https://iss", SAN: "https://OTHER/wf.yml@*"}}}}}
	if err := enforceAttestationPolicy(stateWith(vo), badSig, bundle); err == nil {
		t.Error("verified-offline with a mismatched SAN must refuse")
	}
	if err := enforceAttestationPolicy(stateWith(bvSLSA), &schema.SourceAttestationPolicy{Require: []string{slsa}}, bundle); err != nil {
		t.Errorf("empty allow-list should accept a builder-verified binding: %v", err)
	}
	natState := &schema.AttestationState{Status: "verified", PredicateTypes: []string{slsa}}
	if err := enforceAttestationPolicy(natState, &schema.SourceAttestationPolicy{Require: []string{slsa}}, bundle); err != nil {
		t.Errorf("native predicate should satisfy require with no allow-list: %v", err)
	}
	if err := enforceAttestationPolicy(natState, &schema.SourceAttestationPolicy{Require: []string{slsa}, Builders: keyAllow}, bundle); err == nil {
		t.Error("native predicate must NOT satisfy an identity-pinned require (G1 bypass)")
	}
	if err := enforceAttestationPolicy(nil, &schema.SourceAttestationPolicy{Require: []string{slsa}}, bundle); err == nil {
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
