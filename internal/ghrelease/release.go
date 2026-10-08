package ghrelease

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/trevor-vaughan/polypkg/internal/source"
)

// hexSHA256 matches a lower-case hex SHA-256 digest.
var hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Release is a GitHub release and its assets.
type Release struct {
	Tag        string
	Prerelease bool
	Assets     []Asset
}

// Asset is one release asset. Release guarantees Name is a safe single path
// segment (no separator, no "." or "..", no control or Unicode format
// character), unique in its release, and URL an absolute http(s) URL, https
// whenever the API URL is.
type Asset struct {
	Name   string
	Size   int64
	Digest string // "sha256:<hex>" as GitHub reports it, or "" when it reports none
	URL    string // browser_download_url: fetch it with Download
}

// Release fetches a release of OWNER/REPO: the release tagged tag, or with
// tag "" the repository's latest release (GitHub's latest excludes drafts
// and prereleases). It refuses a response whose tag differs from the one
// asked for, or whose assets fail the checks Asset documents.
func (c *Client) Release(ctx context.Context, owner, repo, tag string) (_ *Release, err error) {
	segs := []string{"releases", "latest"}
	if tag != "" {
		if tag == "." || tag == ".." {
			return nil, fmt.Errorf("invalid release tag %q", tag)
		}
		segs = []string{"releases", "tags", tag}
	}
	endpoint, err := c.repoEndpoint(owner, repo, segs...)
	if err != nil {
		return nil, err
	}
	// Every error below may quote a value decoded from the response.
	defer func() { err = c.scrub(err, endpoint) }()
	var body struct {
		TagName    string `json:"tag_name"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			Name               string `json:"name"`
			Size               int64  `json:"size"`
			Digest             string `json:"digest"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := c.getJSON(ctx, endpoint, &body); err != nil {
		return nil, err
	}
	shown := source.RedactURL(endpoint)
	if body.TagName == "" {
		return nil, fmt.Errorf("release %s has no tag name", shown)
	}
	if tag != "" && body.TagName != tag {
		return nil, fmt.Errorf("release %s: asked for tag %q, got %q", shown, tag, body.TagName)
	}
	rel := &Release{Tag: body.TagName, Prerelease: body.Prerelease, Assets: make([]Asset, 0, len(body.Assets))}
	seen := make(map[string]bool, len(body.Assets))
	for _, a := range body.Assets {
		if err := checkAssetName(a.Name); err != nil {
			return nil, fmt.Errorf("release %q: %w", body.TagName, err)
		}
		if seen[a.Name] {
			return nil, fmt.Errorf("release %q: asset %q is listed twice", body.TagName, a.Name)
		}
		seen[a.Name] = true
		if a.Size < 0 {
			return nil, fmt.Errorf("release %q: asset %q has negative size %d", body.TagName, a.Name, a.Size)
		}
		u, err := url.Parse(a.BrowserDownloadURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, fmt.Errorf("release %q: asset %q has no usable download URL", body.TagName, a.Name)
		}
		if c.api.Scheme == "https" && u.Scheme != "https" {
			return nil, fmt.Errorf("release %q: asset %q download URL is not https", body.TagName, a.Name)
		}
		digest, err := assetDigest(a.Digest)
		if err != nil {
			return nil, fmt.Errorf("release %q: asset %q: %w", body.TagName, a.Name, err)
		}
		rel.Assets = append(rel.Assets, Asset{Name: a.Name, Size: a.Size, Digest: digest, URL: a.BrowserDownloadURL})
	}
	return rel, nil
}

// checkAssetName refuses an asset name that is not a safe single path
// segment. GitHub itself rewrites such names on upload, so one here means a
// broken or hostile API server. Format characters (U+202E RIGHT-TO-LEFT
// OVERRIDE, U+200B ZERO WIDTH SPACE, ...) are refused because they make a
// name display as something it is not. Invalid UTF-8 cannot reach it:
// encoding/json decodes it as U+FFFD.
func checkAssetName(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > maxAssetNameLen ||
		strings.ContainsAny(name, `/\`) || strings.ContainsFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
		return fmt.Errorf("asset name %q is not a safe file name", name)
	}
	return nil
}

// assetDigest normalises an asset's reported digest. A sha256 digest must
// be well formed and is kept; a digest under another algorithm is one this
// package cannot check, so it is reported as none and the caller falls back
// to a checksums file; anything else is malformed.
func assetDigest(d string) (string, error) {
	if d == "" {
		return "", nil
	}
	algo, sum, ok := strings.Cut(d, ":")
	switch {
	case !ok || algo == "":
		return "", fmt.Errorf("malformed digest %q", d)
	case algo != "sha256":
		return "", nil
	case !hexSHA256.MatchString(sum):
		return "", fmt.Errorf("malformed sha256 digest %q", d)
	}
	return d, nil
}
