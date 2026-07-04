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
	return err
}

// fetchCLIError frames a source fetch failure for the user. A network failure
// becomes a single-line unreachable-source message (the http client and the
// planner together printed the URL three times; here it appears once, with the
// transport reason reduced to its most specific tail). A status failure keeps
// the already-clean `fetch <url>: status N` message; only a 404 on a listed
// artifact gets the mid-update hint.
func fetchCLIError(fe *source.FetchError) *CLIError {
	if fe.Network {
		return &CLIError{
			Msg:  fmt.Sprintf("cannot reach source %q at %s: %s", fe.Source, fe.BaseURL, networkReason(fe.Reason())),
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
