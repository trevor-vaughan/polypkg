package mirror

import (
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// claimKeyring is a trust.Keyring that accepts every signature and returns
// fixed claim values. It isolates verifyClaim's claim-vs-entry comparison from
// the cryptography, which TestPullRefusesTamperedArtifact covers end to end.
type claimKeyring map[string]string

func (k claimKeyring) Verify(trust.Role, []byte, string) (trust.Claims, error) {
	return trust.Claims{Values: k}, nil
}

func TestVerifyClaimComparesPlatform(t *testing.T) {
	data := []byte("artifact-bytes")
	hash := contentHash(data)
	// claim binds name/version/hash; plat "" omits the platform field.
	claim := func(plat string) claimKeyring {
		k := claimKeyring{"name": "hello", "version": "1.0.0", "hash": hash}
		if plat != "" {
			k["platform"] = plat
		}
		return k
	}
	cases := []struct {
		name          string
		role          trust.Role
		keyring       claimKeyring
		entryPlatform string
		wantErr       string // "" = accepted
	}{
		{"agnostic entry, any claim", trust.RoleArtifact, claim("any"), "", ""},
		{"platform entry, matching claim", trust.RoleArtifact, claim("linux/amd64"), "linux/amd64", ""},
		{"agnostic entry, platform claim", trust.RoleArtifact, claim("darwin/arm64"), "",
			"signed claim for hello-1.0.0 is for platform darwin/arm64, index entry is for any"},
		{"platform entry, any claim", trust.RoleArtifact, claim("any"), "linux/amd64",
			"signed claim for hello-1.0.0 is for platform any, index entry is for linux/amd64"},
		{"platform entry, other platform claim", trust.RoleArtifact, claim("darwin/arm64"), "linux/amd64",
			"signed claim for hello-1.0.0 is for platform darwin/arm64, index entry is for linux/amd64"},
		{"artifact claim without platform", trust.RoleArtifact, claim(""), "",
			"artifact signature comment missing platform"},
		{"artifact claim with malformed platform", trust.RoleArtifact, claim("../etc"), "",
			`artifact signature comment: platform "../etc" is not <os>/<arch>`},
		{"attestation claim carries no platform", trust.RoleAttestation, claim(""), "linux/amd64", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyClaim(tc.keyring, tc.role, data, "sig", "hello", "1.0.0", tc.entryPlatform, hash)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("verifyClaim: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("verifyClaim error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
