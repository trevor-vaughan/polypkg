package importer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// acmeTool is the repository the github fixture set's genuine bundle names.
const acmeTool = "https://github.com/acme/tool"

// readAttestFixture reads a fixture minted by
// internal/attest/testdata/sigstoregen (-set github).
func readAttestFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "attest", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func githubTrustedMaterial(t *testing.T) root.TrustedMaterial {
	t.Helper()
	tr, err := root.NewTrustedRootFromJSON(readAttestFixture(t, "github-trusted-root.json"))
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func assetSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// tamperSignature flips one bit of the bundle's DSSE signature.
func tamperSignature(t *testing.T, bundle []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(bundle, &doc); err != nil {
		t.Fatal(err)
	}
	sig := doc["dsseEnvelope"].(map[string]any)["signatures"].([]any)[0].(map[string]any)
	raw, err := base64.StdEncoding.DecodeString(sig["sig"].(string))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	sig["sig"] = base64.StdEncoding.EncodeToString(raw)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// unreadablePayload replaces the bundle's DSSE payload with bytes that are not
// base64, so its predicate type cannot be read.
func unreadablePayload(t *testing.T, bundle []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(bundle, &doc); err != nil {
		t.Fatal(err)
	}
	doc["dsseEnvelope"].(map[string]any)["payload"] = "!!! not base64 !!!"
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// withPayload replaces the bundle's DSSE payload with payload, base64-encoded.
func withPayload(t *testing.T, bundle, payload []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(bundle, &doc); err != nil {
		t.Fatal(err)
	}
	doc["dsseEnvelope"].(map[string]any)["payload"] = base64.StdEncoding.EncodeToString(payload)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// bareDSSE wraps an in-toto SLSA statement about sha in a DSSE envelope that
// is not a sigstore bundle.
func bareDSSE(t *testing.T, sha string) []byte {
	t.Helper()
	st, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"name": "tool", "digest": map[string]string{"sha256": sha}}},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate":     map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(st),
		"signatures":  []map[string]string{{"keyid": "k", "sig": "AA=="}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestCheckBundle(t *testing.T) {
	tm := githubTrustedMaterial(t)
	var unrelated schema.SigstoreRoot
	if err := json.Unmarshal(readAttestFixture(t, "unrelated-root.json"), &unrelated); err != nil {
		t.Fatal(err)
	}
	unrelatedTM, err := attest.SigstoreTrustedMaterial(unrelated)
	if err != nil {
		t.Fatal(err)
	}
	asset := assetSHA256(readAttestFixture(t, "github-asset.bin"))
	genuine := readAttestFixture(t, "github-bundle.json")

	for _, c := range []struct {
		name        string
		bundle      []byte
		tm          root.TrustedMaterial
		asset       string
		repo        string
		wantOutcome bundleOutcome
		wantWhy     string
		wantErr     string
	}{
		{"a genuine provenance bundle is kept", genuine, tm, asset, acmeTool, bundleKept, "", ""},
		{"the repository compares case-insensitively", genuine, tm, asset, "https://github.com/ACME/Tool", bundleKept, "", ""},
		{"the repository folds ASCII case only", genuine, tm, asset, "http\u017f://github.com/acme/tool",
			bundleDropped, "dropped a provenance attestation built from \"https://github.com/acme/tool\", not http\u017f://github.com/acme/tool", ""},
		{"another source repository is dropped", readAttestFixture(t, "github-bundle-wrong-repo.json"), tm, asset, acmeTool,
			bundleDropped, `dropped a provenance attestation built from "https://github.com/mallory/tool", not https://github.com/acme/tool`, ""},
		{"another OIDC issuer is dropped", readAttestFixture(t, "github-bundle-wrong-issuer.json"), tm, asset, acmeTool,
			bundleDropped, `dropped a provenance attestation issued to OIDC issuer "https://accounts.google.com", not GitHub Actions`, ""},
		{"a release attestation from GitHub's own CA is skipped unverified", readAttestFixture(t, "github-bundle-release.json"), tm, asset, acmeTool,
			bundleSkipped, `skipped an attestation with predicate type "https://in-toto.io/attestation/release/v0.2"; only SLSA provenance is carried`, ""},
		{"a tampered provenance signature refuses", tamperSignature(t, genuine), tm, asset, acmeTool, 0, "", "does not verify against the Sigstore trusted root: "},
		{"provenance under an unrelated trusted root refuses", genuine, unrelatedTM, asset, acmeTool, 0, "", "does not verify against the Sigstore trusted root: "},
		{"provenance for another asset refuses", genuine, tm, assetSHA256(elfBinary), acmeTool, 0, "", "none of its subjects is this asset"},
		{"an unreadable payload refuses", unreadablePayload(t, genuine), tm, asset, acmeTool, 0, "", "its in-toto statement cannot be read"},
		{"a malformed bundle refuses", []byte(`{"mediaType": 7}`), tm, asset, acmeTool, 0, "", "not a sigstore bundle carrying a DSSE envelope"},
		{"a payload that is not JSON refuses", withPayload(t, genuine, []byte("not json")), tm, asset, acmeTool, 0, "", "its in-toto statement cannot be read"},
		{"a payload with no predicate type refuses", withPayload(t, genuine, []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)), tm, asset, acmeTool,
			0, "", "its in-toto statement cannot be read"},
		{"a non-provenance payload with unknown fields is skipped unparsed",
			withPayload(t, genuine, []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"uri":"pkg:github/acme/tool@v1","digest":{"sha1":"00"}}],"predicateType":"https://example.test/other/v1","extra":true}`)),
			tm, asset, acmeTool, bundleSkipped, `skipped an attestation with predicate type "https://example.test/other/v1"; only SLSA provenance is carried`, ""},
		{"provenance whose subject carries a uri still refuses", withPayload(t, genuine,
			[]byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"uri":"x","digest":{"sha256":"`+asset+`"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{}}`)),
			tm, asset, acmeTool, 0, "", "its in-toto statement cannot be read"},
		{"a DSSE envelope that is not a sigstore bundle refuses", bareDSSE(t, asset), tm, asset, acmeTool, 0, "", "not a sigstore bundle"},
	} {
		t.Run(c.name, func(t *testing.T) {
			outcome, why, err := checkBundle(c.bundle, c.tm, c.asset, c.repo)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("error = %v, want %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkBundle: %v", err)
			}
			if outcome != c.wantOutcome || why != c.wantWhy {
				t.Fatalf("checkBundle = %v, %q; want %v, %q", outcome, why, c.wantOutcome, c.wantWhy)
			}
		})
	}
}

// TestCheckBundleExplainsAVerificationFailure proves the refusal of provenance
// that does not verify carries sigstore-go's reason, quoted, and names both
// causes a user can act on.
func TestCheckBundleExplainsAVerificationFailure(t *testing.T) {
	var unrelated schema.SigstoreRoot
	if err := json.Unmarshal(readAttestFixture(t, "unrelated-root.json"), &unrelated); err != nil {
		t.Fatal(err)
	}
	tm, err := attest.SigstoreTrustedMaterial(unrelated)
	if err != nil {
		t.Fatal(err)
	}
	genuine := readAttestFixture(t, "github-bundle.json")
	v, err := attest.VerifySigstoreBundle(genuine, tm)
	if err != nil || v.Verified || v.FailureReason == "" {
		t.Fatalf("verdict = %+v, %v; want a failure with a reason", v, err)
	}
	_, _, err = checkBundle(genuine, tm, assetSHA256(readAttestFixture(t, "github-asset.bin")), acmeTool)
	var vf *verifyFailure
	if !errors.As(err, &vf) {
		t.Fatalf("error = %v, want a *verifyFailure", err)
	}
	for _, want := range []string{strconv.Quote(v.FailureReason), "tampering", "GitHub Enterprise Server", "private repository"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want it to contain %s", err, want)
		}
	}
}
