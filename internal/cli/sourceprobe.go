package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/spf13/cobra"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/source"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// sourceProbeTimeout bounds the check `source add` makes of a new source, so
// an unresponsive host delays the add by at most this long.
const sourceProbeTimeout = 30 * time.Second

// probeSource checks a source before `source add` records it: it fetches the
// source's signed trust document and verifies it under the trust root pinned
// at trustRootPath, bound to name. It returns "" when that succeeds.
//
// Two answers are refusals, because every later plan would fail the same
// way: a document the pinned key did not sign, and a document bound to
// another source name. Anything else that stops the check (the source is
// unreachable, not published yet, or its metadata has expired) is returned
// as a warning, so a source can be added while offline or before it goes
// live.
func probeSource(cmd *cobra.Command, p *schema.Profile, name, sourceType, sourceURL, trustRootPath string) (warning string, err error) {
	anchor, err := os.ReadFile(trustRootPath) //nolint:gosec // the managed anchor this command just pinned
	if err != nil {
		return "", &CLIError{
			Msg:  fmt.Sprintf("cannot read the trust root pinned at %s", trustRootPath),
			Hint: "check the file's permissions",
			Err:  err,
		}
	}
	// The anchor was validated as a minisign key when it was pinned, so the
	// only refusal left here is a source type with no verifier.
	verifier, err := trust.NewVerifier(sourceType, string(anchor), name)
	if err != nil {
		return "", &CLIError{
			Msg:  fmt.Sprintf("source type %q is not supported", sourceType),
			Hint: "omit --type: polypkg-native is the only source type",
			Err:  err,
		}
	}
	cacheDir, err := os.MkdirTemp("", "polypkg-source-probe-*")
	if err != nil {
		return "", fmt.Errorf("create a scratch directory for the source check: %w", err)
	}
	defer func() { _ = os.RemoveAll(cacheDir) }()

	ctx, cancel := context.WithTimeout(cmd.Context(), sourceProbeTimeout)
	defer cancel()
	backend := source.NewNativeBackend(source.NativeBackendOpts{URL: sourceURL, Source: name, CacheDir: cacheDir})
	doc, sig, err := backend.FetchTrustDoc(ctx)
	if err == nil {
		_, _, _, err = verifier.LoadTrust(doc, sig, 0, "")
	}
	var mm *trust.SourceNameMismatchError
	switch {
	case err == nil:
		return "", nil
	case errors.Is(err, trust.ErrSignatureMismatch):
		return "", &CLIError{
			Msg:  fmt.Sprintf("source %q at %s is not signed by the trust root you gave", name, source.RedactURL(sourceURL)),
			Hint: "pass the trust_root.pub this repository publishes, and check its key id with the publisher (`polypkg repo key show`)",
			Err:  err,
		}
	case errors.As(err, &mm):
		hint := fmt.Sprintf("add it under the name it publishes: `polypkg source add %s --url <url> --trust-root <pub>`", mm.Doc)
		if _, exists := p.Sources.Sources[mm.Doc]; exists {
			hint = fmt.Sprintf("your profile already has a source named %q, which is likely this repository; compare urls with `polypkg source list`", mm.Doc)
		}
		return "", &CLIError{
			Msg:  fmt.Sprintf("source %q at %s publishes source %q", name, source.RedactURL(sourceURL), mm.Doc),
			Hint: hint,
			Err:  err,
		}
	}
	return fmt.Sprintf("could not check source %s at %s now (%s); it is added anyway, and `polypkg plan` reports the problem until it is fixed",
		name, source.RedactURL(sourceURL), probeFailureReason(err)), nil
}

// probeFailureReason says why the check of a new source could not complete,
// for a warning that already names the source and its url: a fetch failure
// that would name them again is reduced to its cause.
func probeFailureReason(err error) string {
	var fe *source.FetchError
	if !errors.As(err, &fe) {
		return err.Error()
	}
	var se *source.StallError
	switch {
	case fe.NotFound():
		return "it does not serve " + path.Base(fe.URL)
	case fe.Network && !errors.As(fe, &se) && !errors.Is(fe, source.ErrInsecureRedirect):
		return "cannot reach it: " + networkReason(fe.Reason())
	default:
		return fetchCLIError(fe).Msg
	}
}
