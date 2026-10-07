package planner

import (
	"fmt"
	"strconv"
	"strings"
)

// TrustRootError reports that a source's trust_root anchor file exists but is
// not a valid minisign public key. The planner is the only layer that knows the
// configured path, so it carries it here; the underlying library detail stays
// in the chain (Unwrap) for logs. The CLI frames the path-aware user message
// and the actionable hint.
type TrustRootError struct {
	Path string
	Err  error
}

func (e *TrustRootError) Error() string {
	return fmt.Sprintf("trust_root %s is not a valid minisign public key", e.Path)
}

func (e *TrustRootError) Unwrap() error { return e.Err }

// ArtifactSignatureError reports that an artifact failed signature
// verification. It deliberately omits the verifier's failure-mode detail (e.g.
// "Invalid signature" vs "signature does not match data") from its message:
// surfacing which check failed would only help an attacker probe the verifier.
// The underlying cause stays in the chain (Unwrap) for operator logs. The CLI
// frames the user message and the corruption/tampering hint.
type ArtifactSignatureError struct {
	Name    string
	Version string
	Source  string
	Err     error
}

func (e *ArtifactSignatureError) Error() string {
	return fmt.Sprintf("signature verification failed for %s-%s from source %q", e.Name, e.Version, e.Source)
}

func (e *ArtifactSignatureError) Unwrap() error { return e.Err }

// ArtifactIdentityError reports that an artifact's own package recipe
// (polypkg.yaml or polypkg.jsonc) does not describe the index entry it was
// fetched for. The signed claim binds the entry's name, version and platform to
// the artifact bytes; this refusal binds the artifact's self-description to the
// same values, so one package cannot be installed under another's name, version
// or platform. Name, Version and Source identify the index entry. Field is
// "name", "version" or "platform"; Got is what the artifact declares and Want is
// what the entry lists, with an agnostic platform rendered as "any". The CLI
// frames the user message and the hint.
type ArtifactIdentityError struct {
	Name    string
	Version string
	Source  string
	Field   string
	Got     string
	Want    string
}

func (e *ArtifactIdentityError) Error() string {
	return fmt.Sprintf("artifact for %s %s from source %q declares %s %q, but the index lists %q",
		e.Name, e.Version, e.Source, e.Field, e.Got, e.Want)
}

// AttestationPolicyError reports that a source's per-predicate attestation gate
// (spec §10.6) refused an install because Predicate is not satisfied at an
// anchored tier from an allowed builder.
//
// RevokedBuilderKeys is the reason the gate is unsatisfiable in the one case
// where "not present" reads as a lie: the package DOES carry a signed
// attestation, but its DSSE signature names a builder key this source's own
// revocation list revokes, so verification never counted it and the binding
// landed at verified-transport-only. Naming the key is what lets the operator
// tell a revocation apart from an ordinary policy miss — `status` already
// reports it as "[builder revoked: …]" and the install path used to not.
type AttestationPolicyError struct {
	Predicate          string
	RevokedBuilderKeys []string
}

func (e *AttestationPolicyError) Error() string {
	msg := fmt.Sprintf("attestation policy: required predicate %q is not present and verified at an anchored tier from an allowed builder", e.Predicate)
	if len(e.RevokedBuilderKeys) > 0 {
		msg += fmt.Sprintf("; a carried attestation for this package is signed by builder key %s, which this source's revocation list revokes",
			quotedList(e.RevokedBuilderKeys))
	}
	return msg
}

// PostureFloorError reports that the TOFU posture floor (spec §10.7, threat G3)
// refused an install: Predicate was verified in the prior generation and is not
// verified now.
//
// NativeBefore and CurrentTier separate two regressions that used to render
// identically. A predicate the prior generation verified NATIVELY (a
// publisher-signed attestation) that the current source merely CARRIES at a
// non-anchored tier is the signature of a source change, not of a tampered or
// downgraded release — most commonly migrating an already-installed package onto
// a `mirror pull` mirror of its own upstream, which re-binds the upstream's
// native attestations as carried-opaque. The remedy for that is not the same as
// the remedy for a publisher who dropped provenance, so the two must not share
// one message. The CLI attaches the remedies.
type PostureFloorError struct {
	Predicate string
	// CurrentTier is the tier the current source's carried binding for
	// Predicate reached ("" when the current source provides it in no form).
	CurrentTier string
	// NativeBefore reports that the prior generation verified Predicate as a
	// native publisher attestation rather than through a carried binding.
	NativeBefore bool
}

// SourceChangeShaped reports whether the regression looks like a source change
// rather than a provenance loss: verified natively before, carried (at any
// tier) now.
func (e *PostureFloorError) SourceChangeShaped() bool {
	return e.NativeBefore && e.CurrentTier != ""
}

func (e *PostureFloorError) Error() string {
	if e.SourceChangeShaped() {
		return fmt.Sprintf(
			"attestation posture floor: predicate %q was verified natively at install but the current source only carries it at tier %q",
			e.Predicate, e.CurrentTier)
	}
	return fmt.Sprintf("attestation posture floor: predicate %q was verified previously but is not verified now", e.Predicate)
}

// quotedList renders ids as a quoted, comma-separated list for an error message.
func quotedList(ids []string) string {
	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = strconv.Quote(id)
	}
	return strings.Join(quoted, ", ")
}
