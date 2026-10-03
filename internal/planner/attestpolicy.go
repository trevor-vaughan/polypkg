package planner

import (
	"bytes"
	"encoding/base64"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// tierAnchored reports whether a carried tier represents cryptographically
// anchored verification whose payload-authoritative predicate type may be
// trusted. verified-transport-only and bound-unverified are self-declared and
// carry no policy weight (spec §10.6, hard constraint a).
func tierAnchored(tier string) bool {
	return tier == schema.CarriedTierBuilderVerified || tier == schema.CarriedTierVerifiedOffline
}

// matchSAN matches a Fulcio SAN against an allow-list pattern: exact, or — when
// the pattern ends with a single trailing "*" — by prefix over the rest (to
// cover the varying @refs/... tail of CI workflow SANs). One wildcard position
// only; a bare "*" or empty pattern is rejected at config validation AND fails
// closed here (defense in depth).
func matchSAN(pattern, san string) bool {
	// Defense in depth: a bare "*" (or empty) pattern matches everything and
	// defeats the allow-list. Config validation (profile-v1.json) already
	// rejects it, but fail closed here too so the invariant does not depend on
	// an external schema.
	if pattern == "*" || pattern == "" {
		return false
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(san, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == san
}

// identityAllowed reports whether binding b's builder identity matches the
// consumer allow-list. An empty allow-list trusts the source's anchored-bundle
// key governance (returns true — a weaker posture that does not mitigate G1).
// A builder-verified binding matches a key entry (its key id resolved through
// the bundle to the ed25519 public key, compared by decoded bytes so base64
// padding never causes a false miss); a verified-offline binding matches a
// sigstore entry (issuer exact, SAN via matchSAN). A binding never matches the
// other kind's entries. Fails closed: a nil/absent bundle key, or an
// undecodable stored/allow-list key, is treated as no match.
func identityAllowed(b *schema.CarriedBinding, allow []schema.BuilderAllowEntry, bundle *trust.Bundle) bool {
	if len(allow) == 0 {
		return true
	}
	for _, e := range allow {
		switch {
		case e.Key != "" && b.Tier == schema.CarriedTierBuilderVerified:
			if bundle == nil {
				continue
			}
			bk, ok := bundle.BuilderKey(b.VerifyingKeyID)
			if !ok {
				continue
			}
			want, werr := base64.StdEncoding.DecodeString(e.Key)
			got, gerr := base64.StdEncoding.DecodeString(bk.PublicKey)
			if werr == nil && gerr == nil && len(want) > 0 && bytes.Equal(want, got) {
				return true
			}
		case e.Sigstore != nil && b.Tier == schema.CarriedTierVerifiedOffline:
			if b.CertificateIssuer == e.Sigstore.Issuer && matchSAN(e.Sigstore.SAN, b.CertificateIdentity) {
				return true
			}
		}
	}
	return false
}

// enforceAttestationPolicy applies a source's per-predicate attestation gate
// (phase 2d-1, spec §10.6) — the first place a carried tier GATES an install.
// Each required predicate type must be present AND verified at an anchored tier
// from an allowed builder identity, else the install is refused (fail closed).
// A nil policy or an empty Require list is a no-op (the source is ungated).
// bundle resolves a builder-verified binding's key id to its public key for
// allow-list matching; it is the same source bundle bindCarriedRefs used.
// revokedBuilderKeys is what bindCarriedRefs observed the source's revocation
// list rejecting while classifying this package's carried envelopes; it does not
// change the verdict, only the error's explanation of it.
func enforceAttestationPolicy(attState *schema.AttestationState, pol *schema.SourceAttestationPolicy, bundle *trust.Bundle, revokedBuilderKeys []string) error {
	if pol == nil || len(pol.Require) == 0 {
		return nil
	}
	var allow []schema.BuilderAllowEntry
	if pol.Builders != nil {
		allow = pol.Builders.Allow
	}
	for _, want := range pol.Require {
		if !requireSatisfied(attState, want, allow, bundle) {
			return &AttestationPolicyError{Predicate: want, RevokedBuilderKeys: revokedBuilderKeys}
		}
	}
	return nil
}

// requireSatisfied reports whether predicate type want is met: by a carried
// binding at an anchored tier (builder-verified or verified-offline) whose
// identity is allowed; or — ONLY when no builder allow-list is configured — by
// a native publisher-verified predicate of that type. Native attestations carry
// no builder identity, so they cannot satisfy an identity-pinned require:
// allowing them would bypass the builder allow-list (threat G1).
func requireSatisfied(attState *schema.AttestationState, want string, allow []schema.BuilderAllowEntry, bundle *trust.Bundle) bool {
	if attState == nil {
		return false
	}
	for i := range attState.CarriedBindings {
		b := &attState.CarriedBindings[i]
		if b.PredicateType != want || !tierAnchored(b.Tier) {
			continue
		}
		if identityAllowed(b, allow, bundle) {
			return true
		}
	}
	if len(allow) == 0 {
		for _, p := range attState.PredicateTypes {
			if p == want {
				return true
			}
		}
	}
	return false
}

// verifiedPredicateTypes returns the set of predicate types a package's
// attestation state proves at a verified posture: every native
// publisher-minisign-verified type (PredicateTypes) plus every carried binding
// at an anchored tier (builder-verified or verified-offline). Transport-only and
// bound-unverified carried bindings are self-declared and excluded. A nil state
// yields nil. Order is unspecified; duplicates are removed.
func verifiedPredicateTypes(state *schema.AttestationState) []string {
	if state == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(state.PredicateTypes)+len(state.CarriedBindings))
	var out []string
	add := func(p string) {
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, p := range state.PredicateTypes {
		add(p)
	}
	for i := range state.CarriedBindings {
		if b := &state.CarriedBindings[i]; tierAnchored(b.Tier) {
			add(b.PredicateType)
		}
	}
	return out
}

// enforcePostureFloor applies the TOFU posture floor (phase 2d-2, spec §10.7,
// threat G3): every predicate type verified in the prior generation must still
// be verified now (native or anchored-carried, identity-agnostic — identity is
// 2d-1's concern). A regressed predicate refuses the install unless the operator
// pinned the exact resolved version (pinnedExact), which explicitly accepts that
// release's lower posture — the same escape hatch as the D15 anti-downgrade
// guard. No prior state (first sighting) is the TOFU baseline and never gates.
// The floor is identity-agnostic (an empty allow-list), so requireSatisfied is
// called with a nil bundle: it is consulted only for anchored-carried presence,
// never for key resolution.
func enforcePostureFloor(newState, prior *schema.AttestationState, pinnedExact bool) error {
	if pinnedExact {
		return nil // the operator pinned this exact version, accepting its posture
	}
	for _, want := range verifiedPredicateTypes(prior) {
		if !requireSatisfied(newState, want, nil, nil) {
			return &PostureFloorError{
				Predicate:    want,
				CurrentTier:  carriedTierFor(newState, want),
				NativeBefore: hasNativePredicate(prior, want),
			}
		}
	}
	return nil
}

// carriedTierFor returns the tier of state's carried binding for predicate type
// want, or "" when state carries no binding of that type. When more than one
// binding shares a type the strongest tier wins, so the message reports the best
// the current source actually managed rather than an arbitrary one.
func carriedTierFor(state *schema.AttestationState, want string) string {
	if state == nil {
		return ""
	}
	best := ""
	for i := range state.CarriedBindings {
		b := &state.CarriedBindings[i]
		if b.PredicateType != want {
			continue
		}
		if best == "" || carriedTierRank(b.Tier) > carriedTierRank(best) {
			best = b.Tier
		}
	}
	return best
}

// carriedTierRank orders carried tiers weakest to strongest. It is used only to
// pick the tier a message reports; policy decisions go through tierAnchored,
// which stays the single source of truth for what counts as verified.
func carriedTierRank(tier string) int {
	switch tier {
	case schema.CarriedTierBoundUnverified:
		return 1
	case schema.CarriedTierVerifiedTransportOnly:
		return 2
	case schema.CarriedTierBuilderVerified:
		return 3
	case schema.CarriedTierVerifiedOffline:
		return 4
	default:
		return 0
	}
}

// hasNativePredicate reports whether state proves want as a native,
// publisher-signed predicate (PredicateTypes) rather than a carried binding.
func hasNativePredicate(state *schema.AttestationState, want string) bool {
	if state == nil {
		return false
	}
	for _, p := range state.PredicateTypes {
		if p == want {
			return true
		}
	}
	return false
}
