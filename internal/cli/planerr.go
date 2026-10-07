package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/source"
)

// planExecError translates the typed failures that planner.Plan surfaces into
// user-facing *CLIError values, adding the hint the origin package deliberately
// omits. Origin packages produce precise factual strings (the resolver names
// the package and lists versions; this boundary frames them for the operator
// and points at the profile knob to turn). Errors with no recognized typed
// cause pass through unchanged so cobra renders them as today.
func planExecError(err error) error {
	if err == nil {
		return nil
	}
	var re *resolver.ResolveError
	if errors.As(err, &re) {
		return resolveCLIError(re)
	}
	var fe *source.FetchError
	if errors.As(err, &fe) {
		return fetchCLIError(fe)
	}
	var tre *planner.TrustRootError
	if errors.As(err, &tre) {
		return &CLIError{
			Msg:  tre.Error(),
			Hint: "trust_root must point at the repository's minisign .pub file",
			Err:  tre,
		}
	}
	var ase *planner.ArtifactSignatureError
	if errors.As(err, &ase) {
		return &CLIError{
			Msg:  ase.Error(),
			Hint: "the artifact does not match its signature; it may be corrupted in transit or tampered with; retry, and if it persists contact the repository operator",
			Err:  ase,
		}
	}
	var pfe *planner.PostureFloorError
	if errors.As(err, &pfe) {
		return postureFloorCLIError(err, pfe)
	}
	var ape *planner.AttestationPolicyError
	if errors.As(err, &ape) {
		return attestationPolicyCLIError(err, ape)
	}
	return err
}

// postureFloorCLIError frames an anti-downgrade posture refusal. The planner's
// message is kept verbatim (the caller prefixed it with name-version), and only
// the remedy differs by shape.
//
// A native-to-carried regression is what an operator sees when they repoint an
// already-installed package at a `mirror pull` mirror of its own upstream: the
// pull re-binds the upstream's native attestations as carried-opaque, so the
// tier genuinely drops and refusing is correct. "Pin the exact version" — the
// only remedy the old message offered — is the worst of the available ones,
// because the floor stays waived for that package as long as the pin is there.
// Re-baselining the one package is narrower and keeps the ratchet running from
// the mirror's tier onward.
func postureFloorCLIError(err error, pfe *planner.PostureFloorError) *CLIError {
	hint := "the source no longer proves this predicate at a verified tier; install from a source that does, or pin the exact version in the profile to accept the lower posture for this package"
	if pfe.SourceChangeShaped() {
		hint = "a `mirror pull` mirror carries its upstream's native attestations as carried-opaque, so an existing install moved onto a mirror of its own upstream trips this floor; keep this package on the source that attests it natively, or re-baseline the floor at the mirror's tier with `polypkg remove <pkg>` then `polypkg install <pkg>`; pin the exact version only to waive the floor while the pin stands"
	}
	return &CLIError{Msg: err.Error(), Hint: hint, Err: err}
}

// attestationPolicyCLIError frames a per-source require-gate refusal. A revoked
// builder key reaches the gate looking exactly like an absent predicate — the
// signature is never counted, so the binding sits at verified-transport-only —
// and the operator needs to know which of the two it is before deciding whether
// to chase the publisher or the profile.
func attestationPolicyCLIError(err error, ape *planner.AttestationPolicyError) *CLIError {
	hint := "the source's attestation.require for this predicate is not met; check the source's published attestations, or relax attestation.require in the profile if you accept the weaker posture"
	if len(ape.RevokedBuilderKeys) > 0 {
		hint = "the provenance is present and correctly signed, but the publisher revoked the signing builder key, so it no longer counts; wait for a release signed by a current key, or contact the repository operator"
	}
	return &CLIError{Msg: err.Error(), Hint: hint, Err: err}
}

// fetchCLIError frames a source fetch failure for the user. A stalled server
// or a refused https→http redirect keeps the clean `fetch <url>: <reason>`
// message (the server was reached, so "cannot reach" would mislead) with its
// own hint. Any other network failure becomes a single-line
// unreachable-source message (the http client and the planner together
// printed the URL three times; here it appears once, with the transport reason
// reduced to its most specific tail). A status failure keeps the already-clean
// `fetch <url>: status N` message; only a 404 on a listed artifact gets the
// mid-update hint.
func fetchCLIError(fe *source.FetchError) *CLIError {
	var se *source.StallError
	if errors.As(fe, &se) {
		return &CLIError{
			Msg:  fe.Error(),
			Hint: "the server stopped sending data or is sending too slowly; retry later, and if it persists contact the repository operator",
			Err:  fe,
		}
	}
	if errors.Is(fe, source.ErrInsecureRedirect) {
		return &CLIError{
			Msg:  fe.Error(),
			Hint: "the server redirected an https request to a non-https URL, which would drop transport security; contact the repository operator",
			Err:  fe,
		}
	}
	if fe.Network {
		return &CLIError{
			Msg:  fmt.Sprintf("cannot reach source %q at %s: %s", fe.Source, source.RedactURL(fe.BaseURL), networkReason(fe.Reason())),
			Hint: "check the source url in your profile and your network connection",
			Err:  fe,
		}
	}
	if fe.Status == 404 && fe.IsArtifact() {
		return &CLIError{
			Msg:  fe.Error(),
			Hint: "the source's index lists this artifact but the server does not serve it; the repository may be mid-update",
			Err:  fe,
		}
	}
	return &CLIError{Msg: fe.Error(), Err: fe}
}

// networkReason reduces a Go transport error string to its most specific tail.
// Dial errors nest as "dial tcp <addr>: connect: connection refused" or
// "dial tcp: lookup <host>: no such host"; the operator wants the final clause
// ("connection refused", "no such host"), not the dial scaffolding. Splitting
// on the last ": " yields it; a string with no separator is returned as-is.
func networkReason(s string) string {
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}

// resolveCLIError frames a resolver failure for the user. The resolver's
// Error() string is already the complete factual message (name, constraint,
// available versions, and the transitive "required via" chain when meaningful);
// this only attaches the actionable hint per failure kind.
func resolveCLIError(re *resolver.ResolveError) *CLIError {
	switch re.Kind {
	case resolver.KindUnknownName:
		return &CLIError{
			Msg:  re.Error(),
			Hint: "check the package name and the sources in your profile",
			Err:  re,
		}
	case resolver.KindNoVersion:
		return &CLIError{
			Msg:  re.Error(),
			Hint: "adjust the version constraint in your profile",
			Err:  re,
		}
	default:
		// KindConflict, KindNoCandidate, KindTooComplex: no single profile knob
		// resolves them, so surface the factual message without a misleading
		// hint.
		return &CLIError{Msg: re.Error(), Err: re}
	}
}
