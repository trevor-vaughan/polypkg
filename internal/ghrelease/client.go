// Package ghrelease is a client for the parts of the GitHub REST API that
// importing a release needs: repository and release metadata, asset
// downloads, and artifact attestations. It knows nothing about polypkg's CLI
// or package schema.
//
// The optional API token is sent only to the API origin (the scheme and host
// of the URL given to New), set on each *http.Request and removed again on
// any redirect that leaves that origin. A token is never sent over plain
// http except to a loopback host. Asset and attestation-bundle
// downloads are never authenticated. No error this package returns contains
// the token or a response body.
package ghrelease

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/source"
)

const (
	// maxAPIResponse caps one REST API JSON response. A release with
	// hundreds of assets, or a page of 100 attestations with inline bundles,
	// is far below it, so it only refuses a broken or hostile server.
	maxAPIResponse = 16 << 20
	// apiVersion pins the REST API version the response shapes below follow.
	apiVersion = "2022-11-28"
	// apiAccept is the media type GitHub documents for REST API requests.
	apiAccept = "application/vnd.github+json"
	// maxRedirects is net/http's default cap, applied when the caller's
	// client has no redirect policy of its own.
	maxRedirects = 10
)

var (
	// ownerName accepts GitHub account (user and organization) names: up to
	// 39 letters, digits, '-' and '_', not starting with '-'. It is a lenient
	// superset of github.com's rule, admitting legacy consecutive and trailing
	// hyphens and the '_' of GitHub Enterprise Server and Enterprise Managed
	// User logins (octocat_acme). Path safety comes from the charset, which
	// has no '.', '/' or '%'.
	ownerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,38}$`)
	// repoName is GitHub's repository name grammar. "." and ".." match it
	// but are refused separately.
	repoName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

// RepositoryNameError refuses an owner or repository name GitHub would not
// accept, before it reaches a URL path.
type RepositoryNameError struct {
	Owner, Repo string
}

func (e *RepositoryNameError) Error() string {
	if !ownerName.MatchString(e.Owner) {
		return fmt.Sprintf("GitHub owner %q is not a valid account name", e.Owner)
	}
	return fmt.Sprintf("GitHub repository %q is not a valid repository name", e.Repo)
}

// ValidateRepository refuses, as a *RepositoryNameError, an owner that is not
// a GitHub account name or a repo that is not a GitHub repository name. Both
// reach request paths, recipe comments and the source-repository URI an
// attestation must name.
func ValidateRepository(owner, repo string) error {
	if !ownerName.MatchString(owner) || !repoName.MatchString(repo) || repo == "." || repo == ".." {
		return &RepositoryNameError{Owner: owner, Repo: repo}
	}
	return nil
}

// APIURLError refuses an API URL: it is not an absolute http(s) URL with a
// host and no credentials, query or fragment, or (Plaintext) it is plain
// http to a host that is not loopback while a token would be sent. URL is
// the URL as given, credentials redacted; Host is its host when it parsed.
type APIURLError struct {
	URL       string
	Host      string
	Plaintext bool
}

func (e *APIURLError) Error() string {
	if e.Plaintext {
		return fmt.Sprintf("refusing to send the API token over plain http to %s: use an https API URL", e.URL)
	}
	return fmt.Sprintf("invalid GitHub API URL %s: want an http(s) URL with a host and no credentials, query or fragment", e.URL)
}

// CheckAPIURL applies New's rules to apiURL, for a caller that wants to
// refuse it before building a client: a *APIURLError when apiURL is not an
// API root, or when haveToken and apiURL is plain http to a host other than
// localhost (any case), 127.0.0.0/8 or ::1.
func CheckAPIURL(apiURL string, haveToken bool) error {
	_, err := parseAPIURL(apiURL, haveToken)
	return err
}

// parseAPIURL is CheckAPIURL returning the parsed URL.
func parseAPIURL(apiURL string, haveToken bool) (*url.URL, error) {
	u, err := url.Parse(apiURL)
	switch {
	case err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "":
		e := &APIURLError{URL: source.RedactURL(apiURL)}
		if err == nil {
			e.Host = u.Host
		}
		return nil, e
	case haveToken && u.Scheme == "http" && !isLoopback(u.Hostname()):
		return nil, &APIURLError{URL: source.RedactURL(apiURL), Host: u.Host, Plaintext: true}
	}
	return u, nil
}

// Client talks to one GitHub REST API host. Build it with New.
type Client struct {
	api    *url.URL // the parsed API base URL; nil when apiErr is set
	apiErr error    // why the apiURL given to New is unusable
	base   string   // the API base URL without a trailing slash
	token  string
	hc     *http.Client
}

// New returns a client for the REST API at apiURL (https://api.github.com,
// or a GitHub Enterprise Server's https://HOST/api/v3). token may be empty;
// when set it is sent as a bearer token on requests to apiURL's scheme and
// host only. hc should come from source.NewHTTPClient, whose idle-read
// deadline and https→non-https redirect refusal apply to every request; a
// nil hc means source.NewHTTPClient() with its defaults. New uses a copy of
// it whose redirect policy also drops the token whenever a redirect leaves
// the API origin. net/http alone would keep the token on a redirect to
// another port or a subdomain of the API host.
//
// An apiURL that is not an absolute http(s) URL with a host, or that carries
// credentials, a query or a fragment, does not fail here: every API call on
// the returned client reports it instead. So does a token with a plain-http
// apiURL, which would send the token in clear, unless the host is loopback
// (localhost, 127.0.0.0/8 or ::1) and the token never leaves the machine.
func New(apiURL, token string, hc *http.Client) *Client {
	c := &Client{token: token}
	if u, err := parseAPIURL(apiURL, token != ""); err != nil {
		c.apiErr = err
	} else {
		c.api = u
		c.base = u.Scheme + "://" + u.Host + strings.TrimSuffix(u.EscapedPath(), "/")
	}
	if hc == nil {
		hc = source.NewHTTPClient()
	}
	client := *hc
	policy := hc.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if policy != nil {
			if err := policy(req, via); err != nil {
				return err
			}
		} else if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		if !c.isAPIOrigin(req.URL) {
			req.Header.Del("Authorization")
		}
		return nil
	}
	c.hc = &client
	return c
}

// isLoopback reports whether host (without port or brackets) names the
// local machine: localhost, or an address in 127.0.0.0/8 or ::1.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isAPIOrigin reports whether u has the API URL's scheme and host (port
// included). Only such requests may carry the token.
func (c *Client) isAPIOrigin(u *url.URL) bool {
	return c.api != nil && u.Scheme == c.api.Scheme && strings.EqualFold(u.Host, c.api.Host)
}

// RateLimitError reports that GitHub refused a request under its primary or
// secondary rate limit: a 403 or 429 carrying X-RateLimit-Remaining: 0 or a
// Retry-After header.
type RateLimitError struct {
	URL           string    // the refused URL, credentials redacted
	Reset         time.Time // when the limit resets; zero when GitHub did not say
	Authenticated bool      // whether the final request, after any redirects, carried the token
}

func (e *RateLimitError) Error() string {
	msg := "GitHub API rate limit exceeded for " + e.URL
	if !e.Reset.IsZero() {
		msg += "; it resets at " + e.Reset.UTC().Format(time.RFC3339)
	}
	return msg
}

// NotFoundError reports a 404 from GitHub. For a private or misspelled
// repository GitHub answers 404 rather than 403.
type NotFoundError struct {
	URL string // the missing URL, credentials redacted
}

func (e *NotFoundError) Error() string {
	return "GET " + e.URL + ": not found"
}

// response is a successful GET: its body, headers and final URL (after any
// redirects).
type response struct {
	body   []byte
	header http.Header
	url    *url.URL
}

// get fetches rawURL and returns its body, refusing more than limit bytes
// (counted as read, whatever Content-Length claims). accept is sent as the
// Accept header. With api set the request carries the API version header
// and, when rawURL is on the API origin, the token.
//
// A 404 is a *NotFoundError, a rate-limit refusal a *RateLimitError, and any
// other non-200 status an error naming the status. Response bodies are never
// quoted in errors, and an API response containing the token, raw or in a
// decoded JSON string, is refused: a hostile server could echo the token
// back to have it printed or sent elsewhere.
func (c *Client) get(ctx context.Context, rawURL, accept string, limit int64, api bool) (*response, error) {
	shown := source.RedactURL(rawURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", shown, unwrapURLError(err))
	}
	req.Header.Set("Accept", accept)
	if api {
		req.Header.Set("X-GitHub-Api-Version", apiVersion)
		if c.token != "" && c.isAPIOrigin(req.URL) {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", shown, unwrapURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusNotFound:
		return nil, &NotFoundError{URL: shown}
	case isRateLimited(resp):
		return nil, newRateLimitError(shown, resp)
	default:
		return nil, fmt.Errorf("GET %s: HTTP %d", shown, resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("GET %s: response of %d bytes exceeds the %d-byte limit", shown, resp.ContentLength, limit)
	}
	// A declared length (already within limit) sizes the buffer up front:
	// growing it by doubling would briefly hold about twice the body. The
	// extra bytes.MinRead lets ReadFrom see EOF without growing again. The
	// server's claim is trusted only up to maxPrealloc, so a lying length
	// cannot force a huge allocation; a larger body grows from there. The
	// cap still counts bytes read, so a body longer than declared is refused
	// all the same.
	buf := new(bytes.Buffer)
	if resp.ContentLength > 0 {
		buf = bytes.NewBuffer(make([]byte, 0, min(resp.ContentLength, maxPrealloc)+bytes.MinRead))
	}
	if _, err := buf.ReadFrom(io.LimitReader(resp.Body, limit+1)); err != nil {
		return nil, fmt.Errorf("GET %s: read body: %w", shown, err)
	}
	body := buf.Bytes()
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("GET %s: response exceeds the %d-byte limit", shown, limit)
	}
	// A real API response never contains the caller's token, raw or
	// JSON-escaped. Refusing one that does keeps every string decoded from it
	// (tag and asset names, descriptions, URLs) safe to print or fetch.
	if api && c.token != "" && (bytes.Contains(body, []byte(c.token)) || jsonStringContains(body, c.token)) {
		return nil, fmt.Errorf("GET %s: %s", shown, echoedToken)
	}
	return &response{body: body, header: resp.Header, url: resp.Request.URL}, nil
}

// maxPrealloc bounds the buffer a response's Content-Length sizes up front.
const maxPrealloc = 64 << 20

// echoedToken is the error text for a response that echoed the token back.
const echoedToken = "the response echoed the API token; refusing it"

// jsonStringContains reports whether any string in the JSON text body, key
// or value, contains s once decoded. It stops quietly at malformed JSON,
// which the caller's own decoding reports.
func jsonStringContains(body []byte, s string) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		if str, ok := tok.(string); ok && strings.Contains(str, s) {
			return true
		}
	}
}

// scrub is the last check before an exported method returns err: when err's
// text contains the token, which only a server echoing it back can cause
// (in a Link header or an unparseable Location header), it returns a fixed
// error naming rawURL instead. Any other err, typed errors included, is
// returned unchanged.
func (c *Client) scrub(err error, rawURL string) error {
	if err == nil || c.token == "" || !strings.Contains(err.Error(), c.token) {
		return err
	}
	return fmt.Errorf("GET %s: %s", source.RedactURL(rawURL), echoedToken)
}

// unwrapURLError drops net/http's *url.Error framing (`Get "<url>": `),
// whose URL is unredacted, keeping its cause so errors.Is still matches
// sentinels such as source.ErrInsecureRedirect.
func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// isRateLimited reports whether resp is GitHub's primary (remaining quota 0)
// or secondary (Retry-After) rate-limit refusal. A bare 403 is a permission
// problem, not a rate limit.
func isRateLimited(resp *http.Response) bool {
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
		return false
	}
	return resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != ""
}

// newRateLimitError builds the error for a rate-limited resp. The reset time
// comes from X-RateLimit-Reset (Unix seconds), else from Retry-After
// (seconds from now); an unparseable value leaves it unknown.
func newRateLimitError(shown string, resp *http.Response) *RateLimitError {
	e := &RateLimitError{URL: shown, Authenticated: resp.Request.Header.Get("Authorization") != ""}
	if s, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil && s > 0 {
		e.Reset = time.Unix(s, 0)
	} else if s, err := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64); err == nil && s >= 0 {
		e.Reset = time.Now().Add(time.Duration(s) * time.Second)
	}
	return e
}

// getJSON GETs the API URL rawURL and decodes its body into v.
func (c *Client) getJSON(ctx context.Context, rawURL string, v any) error {
	resp, err := c.get(ctx, rawURL, apiAccept, maxAPIResponse, true)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(resp.body, v); err != nil {
		return fmt.Errorf("decode %s: %w", source.RedactURL(rawURL), err)
	}
	return nil
}

// repoEndpoint returns the API URL for /repos/OWNER/REPO followed by segs,
// each path-escaped. It refuses an unusable API URL and an owner or repo
// that is not a GitHub name (including "." and "..", which would climb out
// of the /repos path).
func (c *Client) repoEndpoint(owner, repo string, segs ...string) (string, error) {
	if c.apiErr != nil {
		return "", c.apiErr
	}
	if err := ValidateRepository(owner, repo); err != nil {
		return "", fmt.Errorf("invalid GitHub repository %q: %w", owner+"/"+repo, err)
	}
	var b strings.Builder
	b.WriteString(c.base + "/repos/" + owner + "/" + repo)
	for _, s := range segs {
		b.WriteString("/" + url.PathEscape(s))
	}
	return b.String(), nil
}

// Repo is the repository metadata the importer uses.
type Repo struct {
	Description string
}

// Repo fetches GET /repos/OWNER/REPO.
func (c *Client) Repo(ctx context.Context, owner, repo string) (*Repo, error) {
	endpoint, err := c.repoEndpoint(owner, repo)
	if err != nil {
		return nil, err
	}
	var body struct {
		Description string `json:"description"`
	}
	if err := c.getJSON(ctx, endpoint, &body); err != nil {
		return nil, c.scrub(err, endpoint)
	}
	return &Repo{Description: body.Description}, nil
}

// Download fetches rawURL, typically an asset's browser_download_url,
// without the token, and returns its body. It refuses a body of more than
// maxBytes bytes, counting the bytes actually read.
func (c *Client) Download(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	resp, err := c.get(ctx, rawURL, "application/octet-stream", maxBytes, false)
	if err != nil {
		return nil, c.scrub(err, rawURL)
	}
	return resp.body, nil
}
