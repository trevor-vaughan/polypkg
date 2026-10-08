package ghreleasetest_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/klauspost/compress/snappy"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/ghrelease/ghreleasetest"
)

// serve starts rel on an httptest server for the test's lifetime.
func serve(t *testing.T, rel ghreleasetest.Release) (*ghreleasetest.Fake, *httptest.Server) {
	t.Helper()
	fake, err := ghreleasetest.New(rel)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return fake, srv
}

// reply is the status and headers of a response get has already closed.
type reply struct {
	StatusCode int
	Header     http.Header
}

// get fetches url and returns the status, headers, and body.
func get(t *testing.T, url string) (reply, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return reply{StatusCode: resp.StatusCode, Header: resp.Header}, body
}

// Predicate types of the two attestations a Fake serves per attested asset.
const (
	provenanceType = "https://slsa.dev/provenance/v1"
	releaseType    = "https://in-toto.io/attestation/release/v0.2"
)

// fetchBundles follows the attestation listing for sha256Hex to each
// bundle_url and returns the decompressed bundles, keyed by the predicate
// type of their in-toto statement.
func fetchBundles(t *testing.T, base, owner, repo, sha256Hex string) map[string][]byte {
	t.Helper()
	resp, body := get(t, base+"/repos/"+owner+"/"+repo+"/attestations/sha256:"+sha256Hex)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attestations: status %d, body %s", resp.StatusCode, body)
	}
	var list struct {
		Attestations []struct {
			Bundle    json.RawMessage `json:"bundle"`
			BundleURL string          `json:"bundle_url"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode attestations: %v", err)
	}
	bundles := map[string][]byte{}
	for _, a := range list.Attestations {
		if string(a.Bundle) != "null" {
			t.Fatalf("inline bundle = %s, want null (GitHub serves bundle_url only)", a.Bundle)
		}
		resp, compressed := get(t, a.BundleURL)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("bundle_url: status %d", resp.StatusCode)
		}
		bundle, err := snappy.Decode(nil, compressed)
		if err != nil {
			t.Fatalf("snappy block decode: %v", err)
		}
		bundles[statementOf(t, bundle).PredicateType] = bundle
	}
	if len(bundles) != 2 || bundles[provenanceType] == nil || bundles[releaseType] == nil {
		t.Fatalf("got attestations of types %v, want SLSA provenance and a release attestation", keys(bundles))
	}
	return bundles
}

type statement struct {
	PredicateType string           `json:"predicateType"`
	Subject       []map[string]any `json:"subject"`
}

// statementOf decodes the in-toto statement a bundle's DSSE envelope signs.
func statementOf(t *testing.T, bundle []byte) statement {
	t.Helper()
	var b struct {
		DsseEnvelope struct {
			Payload []byte `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	var st statement
	if err := json.Unmarshal(b.DsseEnvelope.Payload, &st); err != nil {
		t.Fatalf("decode statement: %v", err)
	}
	return st
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// leafSourceRepo returns the Source Repository URI extension of the bundle's
// leaf certificate.
func leafSourceRepo(t *testing.T, bundle []byte) string {
	t.Helper()
	var b struct {
		VerificationMaterial struct {
			Certificate struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificate"`
		} `json:"verificationMaterial"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(b.VerificationMaterial.Certificate.RawBytes)
	if err != nil {
		t.Fatalf("decode certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	ext, err := certificate.ParseExtensions(cert.Extensions)
	if err != nil {
		t.Fatalf("parse extensions: %v", err)
	}
	return ext.SourceRepositoryURI
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestAttestationVerifiesOfflineAgainstTheTrustedRoot(t *testing.T) {
	data := []byte("hello release asset")
	fake, srv := serve(t, ghreleasetest.Release{
		Owner: "acme", Repo: "hello", Tag: "v1.0.0",
		Assets: []ghreleasetest.Asset{{Name: "hello_linux_amd64.tar.gz", Data: data, Attest: true}},
	})
	bundle := fetchBundles(t, srv.URL, "acme", "hello", sha256Hex(data))[provenanceType]

	// Round-trip the root through its JSON, as the importer receives it.
	tr, err := root.NewTrustedRootFromJSON(fake.TrustedRoot())
	if err != nil {
		t.Fatalf("parse trusted root: %v", err)
	}
	verdict, err := attest.VerifySigstoreBundle(bundle, tr)
	if err != nil {
		t.Fatalf("VerifySigstoreBundle: %v", err)
	}
	if !verdict.Verified {
		t.Fatal("minted bundle does not verify offline against the fake's trusted root")
	}
	if verdict.CertificateIssuer != ghreleasetest.GitHubActionsIssuer {
		t.Errorf("issuer = %q, want %q", verdict.CertificateIssuer, ghreleasetest.GitHubActionsIssuer)
	}
	wantSAN := "https://github.com/acme/hello/.github/workflows/release.yml@refs/tags/v1.0.0"
	if verdict.CertificateIdentity != wantSAN {
		t.Errorf("SAN = %q, want %q", verdict.CertificateIdentity, wantSAN)
	}
	if len(verdict.Subjects) != 1 || verdict.Subjects[0].Digest["sha256"] != sha256Hex(data) {
		t.Errorf("subjects = %+v, want one subject with the asset's sha256", verdict.Subjects)
	}
	if got := leafSourceRepo(t, bundle); got != "https://github.com/acme/hello" {
		t.Errorf("source repository = %q, want https://github.com/acme/hello", got)
	}
}

func TestAttestationDoesNotVerifyAgainstAnotherFakesRoot(t *testing.T) {
	data := []byte("asset")
	rel := ghreleasetest.Release{
		Owner: "acme", Repo: "hello", Tag: "v1.0.0",
		Assets: []ghreleasetest.Asset{{Name: "hello_linux_amd64.tar.gz", Data: data, Attest: true}},
	}
	_, srv := serve(t, rel)
	other, err := ghreleasetest.New(rel)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tr, err := root.NewTrustedRootFromJSON(other.TrustedRoot())
	if err != nil {
		t.Fatalf("parse trusted root: %v", err)
	}
	verdict, err := attest.VerifySigstoreBundle(fetchBundles(t, srv.URL, "acme", "hello", sha256Hex(data))[provenanceType], tr)
	if err != nil {
		t.Fatalf("VerifySigstoreBundle: %v", err)
	}
	if verdict.Verified {
		t.Fatal("a bundle verified against an unrelated root: every Fake must mint under its own CA")
	}
}

func TestAttestRepoOverridesTheSourceRepository(t *testing.T) {
	data := []byte("asset")
	_, srv := serve(t, ghreleasetest.Release{
		Owner: "acme", Repo: "hello", Tag: "v1.0.0",
		Assets: []ghreleasetest.Asset{{Name: "a.tar.gz", Data: data, Attest: true, AttestRepo: "evil/fork"}},
	})
	if got := leafSourceRepo(t, fetchBundles(t, srv.URL, "acme", "hello", sha256Hex(data))[provenanceType]); got != "https://github.com/evil/fork" {
		t.Fatalf("source repository = %q, want https://github.com/evil/fork", got)
	}
}

type releaseDoc struct {
	TagName    string `json:"tag_name"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name   string  `json:"name"`
		Size   int64   `json:"size"`
		Digest *string `json:"digest"`
		URL    string  `json:"browser_download_url"`
	} `json:"assets"`
}

func decodeRelease(t *testing.T, body []byte) releaseDoc {
	t.Helper()
	var d releaseDoc
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("decode release: %v", err)
	}
	return d
}

func TestReleaseRoutes(t *testing.T) {
	plain, renamed := []byte("plain"), []byte("renamed")
	_, srv := serve(t, ghreleasetest.Release{
		Owner: "acme", Repo: "hello", Tag: "v1.0.0", Description: "Says hello.",
		Assets: []ghreleasetest.Asset{
			{Name: "plain.tar.gz", Data: plain},
			{Name: "lying.tar.gz", Data: renamed, Digest: "sha256:" + sha256Hex([]byte("other"))},
			{Name: "nodigest.tar.gz", Data: renamed, OmitDigest: true},
		},
	})

	resp, body := get(t, srv.URL+"/repos/acme/hello")
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"description":"Says hello."`)) {
		t.Fatalf("repo: %d %s", resp.StatusCode, body)
	}

	for _, path := range []string{"/repos/acme/hello/releases/latest", "/repos/acme/hello/releases/tags/v1.0.0"} {
		resp, body := get(t, srv.URL+path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", path, resp.StatusCode)
		}
		d := decodeRelease(t, body)
		if d.TagName != "v1.0.0" || len(d.Assets) != 3 {
			t.Fatalf("%s: %+v", path, d)
		}
		if d.Assets[0].Digest == nil || *d.Assets[0].Digest != "sha256:"+sha256Hex(plain) || d.Assets[0].Size != int64(len(plain)) {
			t.Errorf("%s: plain asset reported as %+v", path, d.Assets[0])
		}
		if d.Assets[1].Digest == nil || *d.Assets[1].Digest != "sha256:"+sha256Hex([]byte("other")) {
			t.Errorf("%s: overridden digest not reported", path)
		}
		if d.Assets[2].Digest != nil {
			t.Errorf("%s: omitted digest reported as %q", path, *d.Assets[2].Digest)
		}
		resp, got := get(t, d.Assets[0].URL)
		if resp.StatusCode != http.StatusOK || !bytes.Equal(got, plain) {
			t.Errorf("%s: download returned %d %q", path, resp.StatusCode, got)
		}
	}

	for _, path := range []string{
		"/repos/acme/hello/releases/tags/v9.9.9",
		"/repos/acme/other/releases/latest",
		"/repos/acme/hello/attestations/sha256:" + sha256Hex(plain), // not attested
		"/download/v1.0.0/missing.tar.gz",
	} {
		if resp, _ := get(t, srv.URL+path); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestPrereleaseIsNotLatest(t *testing.T) {
	_, srv := serve(t, ghreleasetest.Release{Owner: "acme", Repo: "hello", Tag: "v2.0.0-rc1", Prerelease: true})
	if resp, _ := get(t, srv.URL+"/repos/acme/hello/releases/latest"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("latest: status %d, want 404 for a prerelease-only repository", resp.StatusCode)
	}
	if resp, _ := get(t, srv.URL+"/repos/acme/hello/releases/tags/v2.0.0-rc1"); resp.StatusCode != http.StatusOK {
		t.Fatalf("tag: status %d, want 200", resp.StatusCode)
	}
}

func TestRateLimitedAPI(t *testing.T) {
	_, srv := serve(t, ghreleasetest.Release{Owner: "acme", Repo: "hello", Tag: "v1.0.0", RateLimited: true})
	resp, _ := get(t, srv.URL+"/repos/acme/hello/releases/latest")
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-RateLimit-Remaining") != "0" || resp.Header.Get("X-RateLimit-Reset") == "" {
		t.Fatalf("got %d %v, want 403 with exhausted rate-limit headers", resp.StatusCode, resp.Header)
	}
}

func TestRequestsRecordAuthorization(t *testing.T) {
	fake, srv := serve(t, ghreleasetest.Release{Owner: "acme", Repo: "hello", Tag: "v1.0.0"})
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/repos/acme/hello", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer abc")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	got := fake.Requests()
	if len(got) != 1 || got[0].Path != "/repos/acme/hello" || got[0].Authorization != "Bearer abc" {
		t.Fatalf("requests = %+v", got)
	}
}

func TestTarGz(t *testing.T) {
	b, err := ghreleasetest.TarGz(ghreleasetest.TarEntry{Name: "top/hello", Mode: 0o755, Body: []byte("#!/bin/sh\n")})
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := tar.NewReader(gz).Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != "top/hello" || hdr.Mode != 0o755 || hdr.Typeflag != tar.TypeReg || hdr.Size != int64(len("#!/bin/sh\n")) {
		t.Fatalf("header = %+v", hdr)
	}
}

func TestReleaseAttestationIsShapedAsGitHubsAndDoesNotVerify(t *testing.T) {
	data := []byte("asset")
	fake, srv := serve(t, ghreleasetest.Release{
		Owner: "acme", Repo: "hello", Tag: "v1.0.0",
		Assets: []ghreleasetest.Asset{{Name: "hello_linux_amd64.tar.gz", Data: data, Attest: true}},
	})
	bundle := fetchBundles(t, srv.URL, "acme", "hello", sha256Hex(data))[releaseType]
	st := statementOf(t, bundle)
	if len(st.Subject) != 2 || st.Subject[0]["uri"] != "pkg:github/acme/hello@v1.0.0" || st.Subject[0]["name"] != nil ||
		st.Subject[1]["name"] != "hello_linux_amd64.tar.gz" {
		t.Fatalf("subjects = %v, want the release by purl uri, then the asset by name", st.Subject)
	}
	tr, err := root.NewTrustedRootFromJSON(fake.TrustedRoot())
	if err != nil {
		t.Fatal(err)
	}
	if verdict, err := attest.VerifySigstoreBundle(bundle, tr); err != nil || verdict.Verified {
		t.Fatalf("release attestation verified=%v err=%v against the fake's root; GitHub signs these under a CA that root does not hold", verdict.Verified, err)
	}
}

func TestAttestationsHonourPerPage(t *testing.T) {
	data := []byte("asset")
	_, srv := serve(t, ghreleasetest.Release{
		Owner: "acme", Repo: "hello", Tag: "v1.0.0",
		Assets: []ghreleasetest.Asset{{Name: "a.tar.gz", Data: data, Attest: true}},
	})
	count := func(body []byte) int {
		var list struct {
			Attestations []json.RawMessage `json:"attestations"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatal(err)
		}
		return len(list.Attestations)
	}
	resp, body := get(t, srv.URL+"/repos/acme/hello/attestations/sha256:"+sha256Hex(data)+"?per_page=1")
	next := resp.Header.Get("Link")
	if count(body) != 1 || !strings.Contains(next, `rel="next"`) || !strings.Contains(next, "page=2") {
		t.Fatalf("page 1: %d attestations, Link %q; want 1 and a next link to page 2", count(body), next)
	}
	resp, body = get(t, srv.URL+"/repos/acme/hello/attestations/sha256:"+sha256Hex(data)+"?per_page=1&page=2")
	if count(body) != 1 || resp.Header.Get("Link") != "" {
		t.Fatalf("page 2: %d attestations, Link %q; want 1 and no next link", count(body), resp.Header.Get("Link"))
	}
}

func TestDownloadRedirectsToTheAssetHost(t *testing.T) {
	data := []byte("asset bytes")
	_, srv := serve(t, ghreleasetest.Release{
		Owner: "acme", Repo: "hello", Tag: "v1.0.0",
		Assets: []ghreleasetest.Asset{{Name: "a.tar.gz", Data: data}},
	})
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Get(srv.URL + "/download/v1.0.0/a.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "/objects/") {
		t.Fatalf("download: %d to %q, want 302 to the /objects/ host path", resp.StatusCode, loc)
	}
	if r, got := get(t, srv.URL+loc); r.StatusCode != http.StatusOK || !bytes.Equal(got, data) {
		t.Fatalf("object: %d %q", r.StatusCode, got)
	}
}

func TestRepositoryNamesMatchCaseInsensitively(t *testing.T) {
	_, srv := serve(t, ghreleasetest.Release{Owner: "acme", Repo: "hello", Tag: "v1.0.0"})
	if resp, _ := get(t, srv.URL+"/repos/ACME/Hello/releases/latest"); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200 for differently cased names", resp.StatusCode)
	}
}
