package ghrelease_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/ghrelease"
)

var (
	payload    = []byte("upstream release bytes\n")
	payloadSum = func() string { h := sha256.Sum256(payload); return hex.EncodeToString(h[:]) }()
	otherSum   = strings.Repeat("0", 64)
)

const assetName = "tool-1.0-linux-amd64.tar.gz"

func TestCheckIntegrityVerifies(t *testing.T) {
	cases := []struct {
		name   string
		digest string
		sums   map[string]string
		skip   bool
		want   string
	}{
		{"GitHub digest", "sha256:" + payloadSum, nil, false, ghrelease.IntegrityGitHubDigest},
		{"GitHub digest in upper case", "sha256:" + strings.ToUpper(payloadSum), nil, false, ghrelease.IntegrityGitHubDigest},
		{"GitHub digest wins over checksums", "sha256:" + payloadSum, map[string]string{assetName: otherSum}, false, ghrelease.IntegrityGitHubDigest},
		{"checksums file", "", map[string]string{assetName: payloadSum, "other": otherSum}, false, ghrelease.IntegrityChecksumsFile},
		{"checksums entry in upper case", "", map[string]string{assetName: strings.ToUpper(payloadSum)}, false, ghrelease.IntegrityChecksumsFile},
		{"verified even when skipping is allowed", "sha256:" + payloadSum, nil, true, ghrelease.IntegrityGitHubDigest},
		{"nothing to check, skipping allowed", "", nil, true, ghrelease.IntegrityUnverified},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := ghrelease.Asset{Name: assetName, Digest: c.digest}
			got, err := ghrelease.CheckIntegrity(a, payload, c.sums, c.skip)
			if err != nil {
				t.Fatalf("CheckIntegrity: %v", err)
			}
			if got != c.want {
				t.Fatalf("CheckIntegrity source = %q, want %q", got, c.want)
			}
		})
	}
}

func TestCheckIntegrityRefusesMismatch(t *testing.T) {
	cases := []struct {
		name       string
		digest     string
		sums       map[string]string
		skip       bool
		wantSource string
		wantSum    string
	}{
		{"GitHub digest mismatch", "sha256:" + otherSum, nil, false, ghrelease.IntegrityGitHubDigest, otherSum},
		{"GitHub digest mismatch even with skipping allowed", "sha256:" + otherSum, nil, true, ghrelease.IntegrityGitHubDigest, otherSum},
		{"GitHub digest mismatch despite a matching checksums entry", "sha256:" + otherSum, map[string]string{assetName: payloadSum}, false, ghrelease.IntegrityGitHubDigest, otherSum},
		{"checksums mismatch", "", map[string]string{assetName: otherSum}, false, ghrelease.IntegrityChecksumsFile, otherSum},
		{"checksums mismatch even with skipping allowed", "", map[string]string{assetName: otherSum}, true, ghrelease.IntegrityChecksumsFile, otherSum},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := ghrelease.Asset{Name: assetName, Digest: c.digest}
			got, err := ghrelease.CheckIntegrity(a, payload, c.sums, c.skip)
			var ie *ghrelease.IntegrityError
			if !errors.As(err, &ie) {
				t.Fatalf("CheckIntegrity = (%q, %v), want an *IntegrityError", got, err)
			}
			if got != "" {
				t.Fatalf("CheckIntegrity returned source %q alongside the error", got)
			}
			want := ghrelease.IntegrityError{Asset: assetName, Source: c.wantSource, Want: c.wantSum, Got: payloadSum}
			if *ie != want {
				t.Fatalf("IntegrityError = %+v, want %+v", *ie, want)
			}
			for _, s := range []string{assetName, c.wantSource, payloadSum, c.wantSum} {
				if !strings.Contains(err.Error(), s) {
					t.Fatalf("error %q does not mention %q", err, s)
				}
			}
		})
	}
}

func TestCheckIntegrityRefusesUnverifiable(t *testing.T) {
	cases := []struct {
		name   string
		digest string
		sums   map[string]string
		skip   bool
		want   string
		unver  bool
	}{
		{"no digest, no checksums", "", nil, false, "neither a GitHub digest nor a checksums file", true},
		{"checksums file lacks the asset", "", map[string]string{"other.tar.gz": payloadSum}, false, "no entry in the release's checksums file", false},
		{"checksums file lacks the asset, skipping allowed", "", map[string]string{"other.tar.gz": payloadSum}, true, "no entry in the release's checksums file", false},
		{"empty checksums map", "", map[string]string{}, true, "no entry in the release's checksums file", false},
		{"digest of another algorithm", "sha512:" + payloadSum + payloadSum, nil, true, "not sha256:<64 hex digits>", false},
		{"digest without an algorithm", payloadSum, nil, true, "not sha256:<64 hex digits>", false},
		{"truncated digest", "sha256:" + payloadSum[:63], nil, true, "not sha256:<64 hex digits>", false},
		{"non-hex digest", "sha256:" + strings.Repeat("g", 64), nil, true, "not sha256:<64 hex digits>", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := ghrelease.Asset{Name: assetName, Digest: c.digest}
			got, err := ghrelease.CheckIntegrity(a, payload, c.sums, c.skip)
			if err == nil {
				t.Fatalf("CheckIntegrity = %q, want an error", got)
			}
			if got != "" {
				t.Fatalf("CheckIntegrity returned source %q alongside the error", got)
			}
			if !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), assetName) {
				t.Fatalf("error %q does not name the asset and say %q", err, c.want)
			}
			if errors.Is(err, ghrelease.ErrUnverifiable) != c.unver {
				t.Fatalf("errors.Is(err, ErrUnverifiable) = %v, want %v", !c.unver, c.unver)
			}
			var ie *ghrelease.IntegrityError
			if errors.As(err, &ie) {
				t.Fatalf("error %v is an *IntegrityError; nothing was compared", err)
			}
		})
	}
}

// TestCheckIntegrityQuotesAssetNames pins that every error quotes the
// untrusted asset name, so control bytes in it cannot forge or split the
// message.
func TestCheckIntegrityQuotesAssetNames(t *testing.T) {
	const evil = "tool\nrelease asset ok.tar.gz"
	cases := []struct {
		name   string
		digest string
		sums   map[string]string
	}{
		{"GitHub digest mismatch", "sha256:" + otherSum, nil},
		{"malformed GitHub digest", "md5:00", nil},
		{"checksums mismatch", "", map[string]string{evil: otherSum}},
		{"no checksums entry", "", map[string]string{}},
		{"unverifiable", "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ghrelease.CheckIntegrity(ghrelease.Asset{Name: evil, Digest: c.digest}, payload, c.sums, false)
			if err == nil {
				t.Fatal("CheckIntegrity accepted the asset, want an error")
			}
			if strings.Contains(err.Error(), "\n") || !strings.Contains(err.Error(), `"tool\nrelease asset ok.tar.gz"`) {
				t.Fatalf("error %q does not quote the asset name", err)
			}
		})
	}
}
