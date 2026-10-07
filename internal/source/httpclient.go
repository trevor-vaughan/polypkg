package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// responseHeaderTimeout bounds the wait for a response's headers once the
	// request is sent.
	responseHeaderTimeout = 30 * time.Second
	// IdleReadTimeout is how long a response body may go without delivering a
	// single byte before the fetch fails as stalled. It is twice
	// responseHeaderTimeout and well past the retransmission back-off a lossy
	// link produces, so a slow but live server is never cut off; a server that
	// sends nothing for a full minute mid-body is broken or hostile.
	IdleReadTimeout = 60 * time.Second
	// metadataFetchTimeout bounds a whole fetch of a size-capped metadata file
	// (index, trust document, trust bundle, revocation list, signatures). The
	// largest of these is capped at 16 MiB (maxIndexBytes), so five minutes
	// still allows a link of about 55 KiB/s, while a server that drips one byte
	// just inside IdleReadTimeout can no longer hold a fetch open forever.
	// Artifacts (up to 2 GiB) get only the idle deadline.
	metadataFetchTimeout = 5 * time.Minute
	// maxRedirects matches net/http's default redirect cap.
	maxRedirects = 10
)

// ErrInsecureRedirect reports that a server redirected an https request to a
// non-https URL. Following it would drop transport security for the rest of
// the fetch, so the client refuses.
var ErrInsecureRedirect = errors.New("refused redirect from https to a non-https URL")

// StallError reports that a server stopped making progress on a response
// body: either no byte arrived for Limit (Overall false), or a metadata fetch
// did not complete within Limit (Overall true).
type StallError struct {
	Limit   time.Duration
	Overall bool
}

func (e *StallError) Error() string {
	if e.Overall {
		return fmt.Sprintf("server stalled: response not complete after %s", e.Limit)
	}
	return fmt.Sprintf("server stalled: no data received for %s", e.Limit)
}

// stallCause returns the *StallError that canceled ctx, or nil when ctx is
// live or was canceled for another reason (such as the caller's own context).
func stallCause(ctx context.Context) *StallError {
	var se *StallError
	if errors.As(context.Cause(ctx), &se) {
		return se
	}
	return nil
}

// ClientOption adjusts the client NewHTTPClient builds.
type ClientOption func(*idleTransport)

// WithIdleTimeout sets the client's idle-read deadline in place of
// IdleReadTimeout, typically to shorten it; used by tests and short-lived
// probes.
func WithIdleTimeout(d time.Duration) ClientOption {
	return func(t *idleTransport) { t.limit = d }
}

// NewHTTPClient returns the client for polypkg's outbound HTTP fetches. It is
// derived from the standard transport (preserving proxy, dial, and
// TLS-handshake timeouts), bounds the wait for response headers, fails any
// response body that goes IdleReadTimeout without delivering a byte (a read
// then returns a *StallError), and refuses an https→non-https redirect. It
// sets no whole-request timeout, because artifacts can be large; a caller
// that wants one bounds its request context with context.WithTimeoutCause
// and a *StallError cause. That deadline then surfaces as the *StallError
// whether it fires before the headers arrive (from Do) or mid-body (from
// Read), over HTTP/1.1 or HTTP/2.
//
// Set per-host credentials, such as an Authorization token, on each
// *http.Request, never on a wrapping Transport. net/http strips sensitive
// headers on a cross-host redirect only when they are request headers, and
// this client follows cross-host https→https redirects, so a token added by
// a Transport would be sent to whatever host the redirect names.
func NewHTTPClient(opts ...ClientOption) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = responseHeaderTimeout
	it := &idleTransport{base: tr, limit: IdleReadTimeout}
	for _, opt := range opts {
		opt(it)
	}
	return &http.Client{Transport: it, CheckRedirect: checkRedirect}
}

// checkRedirect is the redirect policy for NewHTTPClient. It keeps net/http's
// cap of 10 redirects and refuses a hop from https to any other scheme.
// Cross-host https→https redirects stay allowed: CDNs and release hosts rely
// on them, and the fetched bytes are signature-verified regardless.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	// Only the destination is named: the caller's error already carries the
	// URL that was requested.
	if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("%w: %s", ErrInsecureRedirect, RedactURL(req.URL.String()))
	}
	return nil
}

// idleTransport gives every response an idle-read deadline. Each request
// runs under its own cancelable context, and the response body is wrapped so
// that limit without a delivered byte cancels that context with a
// *StallError cause. Canceling the request context is what unblocks a body
// read stuck on a silent connection.
type idleTransport struct {
	base  http.RoundTripper
	limit time.Duration
}

func (t *idleTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancelCause(req.Context())
	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		// HTTP/1.1 returns the context's cause here, but the HTTP/2 transport
		// returns the bare ctx.Err(), so a stall cause is restored explicitly.
		// It must be read before cancel(nil), which sets a cause of its own on
		// a context that is still live.
		if se := stallCause(ctx); se != nil {
			err = se
		}
		cancel(nil)
		return nil, err
	}
	resp.Body = newIdleBody(ctx, resp.Body, t.limit, cancel)
	return resp, nil
}

// idleBody is a response body whose request is canceled, with a *StallError
// cause, once limit passes without a Read delivering a byte. Close stops the
// timer and releases the request context.
type idleBody struct {
	ctx    context.Context
	body   io.ReadCloser
	limit  time.Duration
	cancel context.CancelCauseFunc
	timer  *time.Timer
}

// newIdleBody wraps body and starts its idle timer. cancel must cancel ctx,
// the context the request was made with.
func newIdleBody(ctx context.Context, body io.ReadCloser, limit time.Duration, cancel context.CancelCauseFunc) *idleBody {
	b := &idleBody{ctx: ctx, body: body, limit: limit, cancel: cancel}
	b.timer = time.AfterFunc(limit, func() { cancel(&StallError{Limit: limit}) })
	return b
}

// Read resets the idle timer whenever bytes arrive. A read that fails
// because the request was canceled by a stall, whether this body's idle
// deadline or a caller's *StallError-caused deadline, returns that
// *StallError in place of the transport's generic cancellation error.
func (b *idleBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	if n > 0 {
		b.timer.Reset(b.limit)
	}
	if err == nil {
		return n, nil
	}
	// The body has ended, so its idle deadline no longer applies.
	b.timer.Stop()
	if !errors.Is(err, io.EOF) {
		if se := stallCause(b.ctx); se != nil {
			return n, se
		}
	}
	return n, err
}

func (b *idleBody) Close() error {
	b.timer.Stop()
	err := b.body.Close()
	b.cancel(nil)
	return err
}
