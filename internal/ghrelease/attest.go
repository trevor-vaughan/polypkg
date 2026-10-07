package ghrelease

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"

	"github.com/klauspost/compress/snappy"

	"github.com/trevor-vaughan/polypkg/internal/source"
)

const (
	// attestationsPerPage is the page size asked of the attestations
	// endpoint, its documented maximum.
	attestationsPerPage = 100
	// maxAttestationPages bounds pagination. 20 pages is 2000 attestations
	// for one artifact digest; a server still offering a next page after
	// that is broken or hostile.
	maxAttestationPages = 20
	// maxBundleDownload caps a compressed bundle fetched from bundle_url. A
	// sigstore bundle is a few KiB.
	maxBundleDownload = 16 << 20
	// maxBundleBytes caps the total size of the bundles one call returns,
	// inline and decompressed alike. A downloaded bundle is checked against
	// what is left of it using the length its snappy header declares, before
	// anything is allocated.
	maxBundleBytes = 64 << 20
	// maxAttestations caps the attestations one call returns across all
	// pages. A release asset has a handful; more is broken or hostile.
	maxAttestations = 100
)

// linkNext finds the rel="next" target in a Link header value, as GitHub
// writes it: <URL>; rel="next".
var linkNext = regexp.MustCompile(`<([^>]*)>\s*;\s*rel="next"`)

// Attestations returns the sigstore bundles GitHub holds for the artifact
// whose SHA-256 is sha256Hex (lower-case hex) in OWNER/REPO, each as bundle
// JSON, following every page of GET
// /repos/OWNER/REPO/attestations/sha256:HEX. An attestation's inline bundle
// is used when present; otherwise its bundle_url is downloaded without the
// token and decoded as snappy block format. A 404 (no attestations, or
// attestations not available for the repository) or an empty list yields
// no bundles and no error. More than maxAttestations attestations, or
// bundles totalling more than maxBundleBytes, is an error. The bundles are
// not verified here.
func (c *Client) Attestations(ctx context.Context, owner, repo, sha256Hex string) (_ [][]byte, err error) {
	if !hexSHA256.MatchString(sha256Hex) {
		return nil, fmt.Errorf("invalid artifact digest %q: want 64 lower-case hex characters", sha256Hex)
	}
	endpoint, err := c.repoEndpoint(owner, repo, "attestations", "sha256:"+sha256Hex)
	if err != nil {
		return nil, err
	}
	// Every error below may quote a URL or value taken from a response.
	defer func() { err = c.scrub(err, endpoint) }()
	next := fmt.Sprintf("%s?per_page=%d", endpoint, attestationsPerPage)
	var bundles [][]byte
	total := 0
	for page := 0; next != ""; page++ {
		if page == maxAttestationPages {
			return nil, fmt.Errorf("attestations for sha256:%s: more than %d pages", sha256Hex, maxAttestationPages)
		}
		resp, err := c.get(ctx, next, apiAccept, maxAPIResponse, true)
		var nf *NotFoundError
		if page == 0 && errors.As(err, &nf) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		var body struct {
			Attestations []struct {
				Bundle    json.RawMessage `json:"bundle"`
				BundleURL string          `json:"bundle_url"`
			} `json:"attestations"`
		}
		if err := json.Unmarshal(resp.body, &body); err != nil {
			return nil, fmt.Errorf("decode %s: %w", source.RedactURL(next), err)
		}
		for _, a := range body.Attestations {
			if len(bundles) == maxAttestations {
				return nil, fmt.Errorf("attestations for sha256:%s: more than %d attestations", sha256Hex, maxAttestations)
			}
			b, err := c.bundle(ctx, a.Bundle, a.BundleURL, maxBundleBytes-total)
			if err != nil {
				return nil, fmt.Errorf("attestation for sha256:%s: %w", sha256Hex, err)
			}
			total += len(b)
			bundles = append(bundles, b)
		}
		if next, err = c.nextPage(resp); err != nil {
			return nil, err
		}
	}
	return bundles, nil
}

// bundle returns an attestation's bundle JSON: inline when GitHub sent it,
// else downloaded from bundleURL and snappy-decoded. An inline bundle must
// be a JSON object, and bundleURL must be https whenever the API URL is.
// It refuses a bundle of more than budget bytes, the part of
// maxBundleBytes earlier bundles left.
func (c *Client) bundle(ctx context.Context, inline json.RawMessage, bundleURL string, budget int) ([]byte, error) {
	if len(inline) > 0 && !bytes.Equal(inline, []byte("null")) {
		if len(inline) > budget {
			return nil, fmt.Errorf("inline bundle of %d bytes would take the bundles past the %d-byte total limit",
				len(inline), maxBundleBytes)
		}
		if inline[0] != '{' {
			return nil, errors.New("inline bundle is not a JSON object")
		}
		return inline, nil
	}
	if bundleURL == "" {
		return nil, errors.New("neither an inline bundle nor a bundle_url")
	}
	shown := source.RedactURL(bundleURL)
	if u, err := url.Parse(bundleURL); c.api.Scheme == "https" && (err != nil || u.Scheme != "https") {
		return nil, fmt.Errorf("bundle_url %s is not an https URL, though the API is", shown)
	}
	blob, err := c.Download(ctx, bundleURL, maxBundleDownload)
	if err != nil {
		return nil, err
	}
	n, err := snappy.DecodedLen(blob)
	if err != nil {
		return nil, fmt.Errorf("bundle from %s: snappy header: %w", shown, err)
	}
	if n > budget {
		return nil, fmt.Errorf("bundle from %s: decoded size %d would take the bundles past the %d-byte total limit",
			shown, n, maxBundleBytes)
	}
	out, err := snappy.Decode(nil, blob)
	if err != nil {
		return nil, fmt.Errorf("bundle from %s: snappy decode: %w", shown, err)
	}
	if !json.Valid(out) {
		return nil, fmt.Errorf("bundle from %s is not JSON", shown)
	}
	return out, nil
}

// nextPage returns the absolute URL of the page after resp, or "" on the
// last page. A next link is resolved against resp's final URL and must stay
// on the API origin: the token goes only there, and pagination that wanders
// to another host is not GitHub's.
func (c *Client) nextPage(resp *response) (string, error) {
	for _, v := range resp.header.Values("Link") {
		m := linkNext.FindStringSubmatch(v)
		if m == nil {
			continue
		}
		u, err := resp.url.Parse(m[1])
		if err != nil || !c.isAPIOrigin(u) {
			return "", fmt.Errorf("pagination link %s leaves the GitHub API origin", source.RedactURL(m[1]))
		}
		return u.String(), nil
	}
	return "", nil
}
