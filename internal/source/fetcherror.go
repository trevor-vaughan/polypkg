package source

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// repoMetaNames are the fixed repository-metadata filenames a native source
// serves (and their detached signatures). A 404 on one of these means the
// source URL is wrong or the repository is not a polypkg repo — a different
// problem from a 404 on a listed artifact, so the CLI frames them differently.
var repoMetaNames = map[string]bool{
	"index.json":                true,
	"index.json.minisig":        true,
	"trust.json":                true,
	"trust.json.minisig":        true,
	"trust-bundle.json":         true,
	"trust-bundle.json.minisig": true,
	"revocations.json":          true,
	"revocations.json.minisig":  true,
}

// FetchError is a typed failure from fetching a resource over a source backend.
// It carries the structured facts the CLI boundary needs to frame a single,
// non-redundant message: which source failed, its base URL, the full URL, and
// whether the failure was a transport/network problem or an HTTP status. The
// net/http client's *url.Error stringifies as `Get "<url>": <cause>`, which —
// once this error is already wrapped with the URL by callers and again by the
// planner — printed the URL three times. We unwrap that here so the underlying
// cause is reported once, cleanly.
type FetchError struct {
	Source  string // the source's name in the profile (NativeBackendOpts.Source)
	BaseURL string // the source's configured base URL
	URL     string // the full URL that was fetched
	Status  int    // HTTP status when the failure was a non-200 response, else 0
	Network bool   // true for a transport-level failure (refused, DNS, timeout)
	Err     error  // underlying cause, with any *url.Error unwrapped
}

// Error names the fetched URL with any credentials redacted (RedactURL). The
// raw URL stays in the URL field for callers that need it.
func (e *FetchError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("fetch %s: status %d", RedactURL(e.URL), e.Status)
	}
	return fmt.Sprintf("fetch %s: %s", RedactURL(e.URL), e.Reason())
}

// RedactURL renders rawURL for an error message or log line without its
// credentials. It is the one redaction rule for URLs in polypkg's messages.
//
//   - A parseable URL with userinfo has the whole userinfo replaced by
//     "xxxxx", user name included: a user-name-only token
//     (https://TOKEN@host/) is as secret as a password, and url.Redacted
//     masks only the password.
//   - Every query value is replaced by "xxxxx" and only the parameter names
//     are kept (a parameter with no value is replaced whole): tokens and
//     signatures travel in the query under too many names to list.
//   - A non-empty fragment is replaced whole by "xxxxx": it can carry a
//     token too (#access_token=...).
//   - A URL that does not parse, or that parses without a host but still
//     contains '@' (an opaque "user:secret@host" or a scheme-less
//     "TOKEN@host/path"), fails closed: only its scheme survives, as
//     "<scheme>://<redacted>", or "<redacted>" when it has none. Nothing that
//     could be userinfo is guessed at and kept.
//
// Accepted limitation: an unescaped '/' inside the userinfo
// (https://ab/cd@host/r) parses with host "ab" and path "/cd@host/r", so it
// is rendered as is. No HTTP client would send "ab/cd" as a credential, since
// it reads that URL the same way, so nothing secret is exposed in practice.
func RedactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err == nil {
		u.RawQuery = redactQuery(u.RawQuery)
		if u.Fragment != "" {
			u.Fragment, u.RawFragment = "xxxxx", ""
		}
		if u.User != nil {
			u.User = url.User("xxxxx")
			return u.String()
		}
		if u.Host != "" || !strings.Contains(rawURL, "@") {
			return u.String()
		}
	}
	if i := strings.Index(rawURL, "://"); i > 0 && urlScheme.MatchString(rawURL[:i]) {
		return rawURL[:i] + "://<redacted>"
	}
	return "<redacted>"
}

// redactQuery keeps a raw query's parameter names and replaces every value
// with "xxxxx". Query strings carry credentials under many names (token,
// access_token, sig, X-Amz-Signature, ...), so no value is kept. A parameter
// with no '=' may itself be the secret, so it is replaced whole.
func redactQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	params := strings.Split(rawQuery, "&")
	for i, p := range params {
		if name, _, ok := strings.Cut(p, "="); ok {
			params[i] = name + "=xxxxx"
		} else {
			params[i] = "xxxxx"
		}
	}
	return strings.Join(params, "&")
}

// urlScheme is RFC 3986's scheme production.
var urlScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*$`)

func (e *FetchError) Unwrap() error { return e.Err }

// NotFound reports whether the fetched file does not exist: an HTTP 404 from
// a served source, or a missing file under a local one.
func (e *FetchError) NotFound() bool {
	return e.Status == http.StatusNotFound || errors.Is(e.Err, fs.ErrNotExist)
}

// IsArtifact reports whether the failed fetch targeted a listed package
// artifact (or its signature) rather than repository metadata (index/trust and
// their signatures). The CLI uses this to attach the "index lists this artifact
// but the server does not serve it" hint only where it applies.
func (e *FetchError) IsArtifact() bool {
	return !repoMetaNames[path.Base(e.URL)]
}

// Reason returns just the underlying cause, without the URL prefix. For a
// network failure this is the transport reason (e.g. "connection refused")
// with the http client's redundant Get "<url>": framing already stripped.
func (e *FetchError) Reason() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

// newNetworkFetchError builds a FetchError for a transport-level failure,
// unwrapping the *url.Error the http client returns so the doubled
// Get "<url>": prefix does not survive into the message.
func newNetworkFetchError(source, baseURL, fullURL string, err error) *FetchError {
	cause := err
	var ue *url.Error
	if errors.As(err, &ue) {
		cause = ue.Err
	}
	return &FetchError{
		Source:  source,
		BaseURL: baseURL,
		URL:     fullURL,
		Network: true,
		Err:     cause,
	}
}

// newStatusFetchError builds a FetchError for a non-200 HTTP response. The
// message stays in the already-clean `fetch <url>: status N` form.
func newStatusFetchError(source, baseURL, fullURL string, status int) *FetchError {
	return &FetchError{
		Source:  source,
		BaseURL: baseURL,
		URL:     fullURL,
		Status:  status,
		Err:     fmt.Errorf("status %d", status),
	}
}
