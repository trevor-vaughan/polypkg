package repo

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// publicGoodTrustedRoot is a verbatim copy of the Sigstore public-good
// trusted_root.json shipped as a TUF target in github.com/sigstore/sigstore
// v1.10.8 (pkg/tuf/repository/targets/trusted_root.json, Apache-2.0). It has
// two Fulcio CAs (2021-03-07..2022-12-31T23:59:59.999Z, and an open-ended one
// from 2022-04-13T20:06:15Z), one open-ended Rekor key, and two CT log keys
// (2021-03-14..2022-10-31T23:59:59.999Z, and open-ended from 2022-10-20).
const publicGoodTrustedRoot = "testdata/sigstore-public-good-trusted-root.json"

// loadTrustedRootDoc reads a trusted_root.json into a generic map so a test
// can mutate one field and write the result back out with writeTrustedRootDoc.
func loadTrustedRootDoc(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// writeTrustedRootDoc marshals doc into dir/name and returns the path.
func writeTrustedRootDoc(t *testing.T, dir, name string, doc map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// docList returns doc[key] as a list of objects, failing the test otherwise.
func docList(t *testing.T, doc map[string]any, key string) []map[string]any {
	t.Helper()
	items, ok := doc[key].([]any)
	if !ok {
		t.Fatalf("trusted root %q is %T, want a list", key, doc[key])
	}
	out := make([]map[string]any, len(items))
	for i, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			t.Fatalf("trusted root %q[%d] is %T, want an object", key, i, it)
		}
		out[i] = m
	}
	return out
}

// publicKeyOf returns the publicKey object of one tlogs/ctlogs entry.
func publicKeyOf(t *testing.T, log map[string]any) map[string]any {
	t.Helper()
	pk, ok := log["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("log publicKey is %T, want an object", log["publicKey"])
	}
	return pk
}

func TestSigstoreRootsFromPublicGoodTrustedRoot(t *testing.T) {
	roots, err := sigstoreRootsFromFile("public-good.json", publicGoodTrustedRoot)
	if err != nil {
		t.Fatalf("sigstoreRootsFromFile: %v", err)
	}
	if len(roots) != 2 {
		t.Fatalf("got %d roots, want one per Fulcio CA (2)", len(roots))
	}

	// Newest CA first, so a bundle from the CA-rotation overlap tries it first.
	if roots[0].ValidFrom != "2022-04-13T20:06:15Z" || roots[0].ValidUntil != "" {
		t.Fatalf("roots[0] window = %q..%q, want 2022-04-13T20:06:15Z, open-ended", roots[0].ValidFrom, roots[0].ValidUntil)
	}
	if roots[1].ValidFrom != "2021-03-07T03:20:29Z" || roots[1].ValidUntil != "2022-12-31T23:59:59.999Z" {
		t.Fatalf("roots[1] window = %q..%q, want 2021-03-07T03:20:29Z..2022-12-31T23:59:59.999Z (sub-second precision kept)", roots[1].ValidFrom, roots[1].ValidUntil)
	}
	if len(roots[0].FulcioCA) != 2 || len(roots[1].FulcioCA) != 1 {
		t.Fatalf("Fulcio chain lengths = %d, %d, want 2 (root + intermediate) and 1 (root)", len(roots[0].FulcioCA), len(roots[1].FulcioCA))
	}

	doc := loadTrustedRootDoc(t, publicGoodTrustedRoot)
	rekorKey := publicKeyOf(t, docList(t, doc, "tlogs")[0])["rawBytes"]
	for i := range roots {
		if !reflect.DeepEqual(roots[i].RekorKeys, []string{rekorKey.(string)}) {
			t.Fatalf("roots[%d].RekorKeys = %q, want the public-good Rekor key", i, roots[i].RekorKeys)
		}
		// Both CT logs overlap both CA windows (the 2022 CT log starts
		// 2022-10-20, before the first CA ends on 2022-12-31).
		if len(roots[i].CTLogKeys) != 2 {
			t.Fatalf("roots[%d].CTLogKeys has %d keys, want 2", i, len(roots[i].CTLogKeys))
		}
		if _, err := attest.SigstoreTrustedMaterial(roots[i]); err != nil {
			t.Fatalf("roots[%d] is not loadable by consumers: %v", i, err)
		}
	}
}

// currentPublicGoodTrustedRoot is a verbatim copy of the Sigstore public-good
// trusted_root.json from github.com/sigstore/root-signing
// (targets/trusted_root.json at commit
// 63134820c97beb38a82a7d34221f4c3db8215df5, Apache-2.0; sha256
// 6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66). Beyond
// the older fixture it lists a Rekor v2 log (log2025-1.rekor.sigstore.dev, an
// Ed25519 key) whose declared log id is not the SHA-256 of its key.
const currentPublicGoodTrustedRoot = "testdata/sigstore-public-good-trusted-root-rekor-v2.json"

// TestSigstoreRootsSkipLogsConsumersCannotMatch pins that a log key declared
// under a log id other than the SHA-256 of its DER is left out: consumers
// re-derive every log id that way, so the key could never match a bundle.
func TestSigstoreRootsSkipLogsConsumersCannotMatch(t *testing.T) {
	roots, err := sigstoreRootsFromFile("current.json", currentPublicGoodTrustedRoot)
	if err != nil {
		t.Fatalf("sigstoreRootsFromFile: %v", err)
	}
	if len(roots) != 2 {
		t.Fatalf("got %d roots, want one per Fulcio CA (2)", len(roots))
	}
	doc := loadTrustedRootDoc(t, currentPublicGoodTrustedRoot)
	var v1Key, v2Key string
	for _, l := range docList(t, doc, "tlogs") {
		key := publicKeyOf(t, l)["rawBytes"].(string)
		switch l["baseUrl"] {
		case "https://rekor.sigstore.dev":
			v1Key = key
		case "https://log2025-1.rekor.sigstore.dev":
			v2Key = key
		}
	}
	if v1Key == "" || v2Key == "" {
		t.Fatal("fixture no longer lists both the v1 and the log2025-1 Rekor logs")
	}
	for i := range roots {
		if !reflect.DeepEqual(roots[i].RekorKeys, []string{v1Key}) {
			t.Fatalf("roots[%d].RekorKeys = %q, want only the v1 Rekor key (the log2025-1 key %q must be skipped)", i, roots[i].RekorKeys, v2Key)
		}
		if len(roots[i].CTLogKeys) != 2 {
			t.Fatalf("roots[%d].CTLogKeys has %d keys, want both CT logs", i, len(roots[i].CTLogKeys))
		}
	}

	// A CT log under a mismatched id is skipped the same way.
	ct := docList(t, doc, "ctlogs")[0]
	ct["logId"] = map[string]any{"keyId": base64.StdEncoding.EncodeToString(make([]byte, 32))}
	p := writeTrustedRootDoc(t, t.TempDir(), "trusted_root.json", doc)
	roots, err = sigstoreRootsFromFile("trusted_root.json", p)
	if err != nil {
		t.Fatalf("sigstoreRootsFromFile: %v", err)
	}
	if len(roots[0].CTLogKeys) != 1 {
		t.Fatalf("CTLogKeys = %d keys, want 1 (the CT log under a mismatched id is skipped)", len(roots[0].CTLogKeys))
	}
}

func TestSigstoreRootsKeepOnlyOverlappingCTKeys(t *testing.T) {
	doc := loadTrustedRootDoc(t, publicGoodTrustedRoot)
	// Move the open-ended 2022 CT log past the first CA's end
	// (2022-12-31T23:59:59.999Z): it must drop out of that CA's root only.
	for _, l := range docList(t, doc, "ctlogs") {
		vf := publicKeyOf(t, l)["validFor"].(map[string]any)
		if _, bounded := vf["end"]; !bounded {
			vf["start"] = "2023-06-01T00:00:00Z"
		}
	}
	p := writeTrustedRootDoc(t, t.TempDir(), "trusted_root.json", doc)

	roots, err := sigstoreRootsFromFile("trusted_root.json", p)
	if err != nil {
		t.Fatalf("sigstoreRootsFromFile: %v", err)
	}
	if len(roots[0].CTLogKeys) != 2 {
		t.Fatalf("open-ended CA kept %d CT keys, want 2", len(roots[0].CTLogKeys))
	}
	if len(roots[1].CTLogKeys) != 1 {
		t.Fatalf("CA ending 2022-12-31 kept %d CT keys, want 1 (the 2023 log does not overlap it)", len(roots[1].CTLogKeys))
	}
}

// trustedRootFor renders a minimal trusted_root.json that carries exactly the
// trust material of r: its Fulcio chain (sigstore orders certificates leaf to
// root, so the self-signed root goes last), its Rekor keys as ECDSA P-256 logs
// whose log id is the SHA-256 of the key's DER, and r's window on the CA.
func trustedRootFor(t *testing.T, r schema.SigstoreRoot) []byte {
	t.Helper()
	window := map[string]any{"start": r.ValidFrom}
	if r.ValidUntil != "" {
		window["end"] = r.ValidUntil
	}
	// sigstoregen writes the root first, then intermediates.
	certs := make([]any, 0, len(r.FulcioCA))
	for i := len(r.FulcioCA) - 1; i >= 0; i-- {
		certs = append(certs, map[string]any{"rawBytes": r.FulcioCA[i]})
	}
	tlogs := make([]any, 0, len(r.RekorKeys))
	for _, k := range r.RekorKeys {
		der, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			t.Fatal(err)
		}
		id := sha256.Sum256(der)
		tlogs = append(tlogs, map[string]any{
			"baseUrl":       "https://rekor.example.test",
			"hashAlgorithm": "SHA2_256",
			"publicKey": map[string]any{
				"rawBytes":   k,
				"keyDetails": "PKIX_ECDSA_P256_SHA_256",
				"validFor":   map[string]any{"start": r.ValidFrom},
			},
			"logId": map[string]any{"keyId": base64.StdEncoding.EncodeToString(id[:])},
		})
	}
	raw, err := json.Marshal(map[string]any{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs":     tlogs,
		"certificateAuthorities": []any{map[string]any{
			"subject":   map[string]any{"organization": "example", "commonName": "example"},
			"uri":       "https://fulcio.example.test",
			"certChain": map[string]any{"certificates": certs},
			"validFor":  window,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestSigstoreRootsRoundTripVerifiesBundle proves the conversion is the one
// consumers need: the offline fixture root, rendered as a trusted_root.json
// and converted back, equals the original mirrored root and verifies the
// fixture bundle it was minted with.
func TestSigstoreRootsRoundTripVerifiesBundle(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "attest", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var want schema.SigstoreRoot
	if err := json.Unmarshal(read("bindable-root.json"), &want); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "trusted_root.json")
	if err := os.WriteFile(p, trustedRootFor(t, want), 0o644); err != nil {
		t.Fatal(err)
	}

	roots, err := sigstoreRootsFromFile("trusted_root.json", p)
	if err != nil {
		t.Fatalf("sigstoreRootsFromFile: %v", err)
	}
	if len(roots) != 1 || !reflect.DeepEqual(roots[0], want) {
		t.Fatalf("converted roots = %+v, want exactly %+v", roots, want)
	}
	tm, err := attest.SigstoreTrustedMaterial(roots[0])
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := attest.VerifySigstoreBundle(read("bindable-bundle.json"), tm)
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Verified {
		t.Fatal("the fixture bundle does not verify against the converted root")
	}
}

func TestSigstoreRootsRejectBadFiles(t *testing.T) {
	mutate := func(edit func(doc map[string]any)) func(t *testing.T, dir string) string {
		return func(t *testing.T, dir string) string {
			doc := loadTrustedRootDoc(t, publicGoodTrustedRoot)
			edit(doc)
			return writeTrustedRootDoc(t, dir, "bad-root.json", doc)
		}
	}
	firstCA := func(doc map[string]any) map[string]any {
		return doc["certificateAuthorities"].([]any)[0].(map[string]any)
	}
	cases := []struct {
		name  string
		write func(t *testing.T, dir string) string
		want  string
	}{
		{"missing file", func(_ *testing.T, dir string) string { return filepath.Join(dir, "bad-root.json") }, "cannot read sigstore root bad-root.json"},
		{"not JSON", func(t *testing.T, dir string) string {
			p := filepath.Join(dir, "bad-root.json")
			if err := os.WriteFile(p, []byte("not json"), 0o644); err != nil {
				t.Fatal(err)
			}
			return p
		}, "sigstore root bad-root.json is not a valid sigstore trusted root"},
		{"wrong media type", mutate(func(doc map[string]any) {
			doc["mediaType"] = "application/vnd.dev.sigstore.trustedroot+json;version=9"
		}), "sigstore root bad-root.json is not a valid sigstore trusted root"},
		{"no certificate authority", mutate(func(doc map[string]any) {
			delete(doc, "certificateAuthorities")
		}), "sigstore root bad-root.json lists no Fulcio certificate authority"},
		{"CA without a validity window", mutate(func(doc map[string]any) {
			delete(firstCA(doc), "validFor")
		}), "with no validity start"},
		{"CA ending before it starts", mutate(func(doc map[string]any) {
			firstCA(doc)["validFor"] = map[string]any{"start": "2022-01-01T00:00:00Z", "end": "2021-01-01T00:00:00Z"}
		}), "whose validity ends before it starts"},
		{"no Rekor key overlaps a CA", mutate(func(doc map[string]any) {
			// The Rekor key now starts after the 2021 CA has ended.
			tl := doc["tlogs"].([]any)[0].(map[string]any)
			tl["publicKey"].(map[string]any)["validFor"] = map[string]any{"start": "2030-01-01T00:00:00Z"}
		}), "has no Rekor log key whose validity overlaps its certificate authority"},
		{"only Rekor key has a log id consumers cannot derive", mutate(func(doc map[string]any) {
			// Consumers derive a log id as the SHA-256 of the key's DER, so a
			// key declared under any other id is skipped, leaving none.
			tl := doc["tlogs"].([]any)[0].(map[string]any)
			tl["logId"] = map[string]any{"keyId": base64.StdEncoding.EncodeToString(make([]byte, 32))}
		}), "has no Rekor log key whose validity overlaps its certificate authority"},
		{"CA chain without a self-signed root", mutate(func(doc map[string]any) {
			// Keep only the intermediate of the two-certificate (2022) chain.
			for _, ca := range doc["certificateAuthorities"].([]any) {
				chain := ca.(map[string]any)["certChain"].(map[string]any)
				if certs := chain["certificates"].([]any); len(certs) == 2 {
					chain["certificates"] = certs[:1]
				}
			}
		}), "consumers cannot load"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.write(t, t.TempDir())
			_, err := sigstoreRootsFromFile("bad-root.json", p)
			if err == nil {
				t.Fatal("expected an error")
			}
			var pe *PublishError
			if !errors.As(err, &pe) {
				t.Fatalf("error is %T, want *PublishError: %v", err, err)
			}
			if !strings.Contains(pe.Msg, "bad-root.json") || !strings.Contains(pe.Msg, tc.want) {
				t.Fatalf("Msg = %q, want it to name the file and contain %q", pe.Msg, tc.want)
			}
			if !strings.Contains(pe.Hint, "sigstore_roots") {
				t.Fatalf("Hint = %q, want it to point at sigstore_roots", pe.Hint)
			}
		})
	}
}

func TestWindowsOverlap(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	var open time.Time
	cases := []struct {
		name                       string
		aStart, aEnd, bStart, bEnd time.Time
		want                       bool
	}{
		{"b inside a", at("2020-01-01T00:00:00Z"), at("2030-01-01T00:00:00Z"), at("2021-01-01T00:00:00Z"), at("2022-01-01T00:00:00Z"), true},
		{"b straddles a's start", at("2021-01-01T00:00:00Z"), at("2030-01-01T00:00:00Z"), at("2020-01-01T00:00:00Z"), at("2022-01-01T00:00:00Z"), true},
		{"b ends exactly at a's start", at("2021-01-01T00:00:00Z"), at("2030-01-01T00:00:00Z"), at("2020-01-01T00:00:00Z"), at("2021-01-01T00:00:00Z"), true},
		{"b starts exactly at a's end", at("2020-01-01T00:00:00Z"), at("2021-01-01T00:00:00Z"), at("2021-01-01T00:00:00Z"), open, true},
		{"b ends before a", at("2021-01-01T00:00:00Z"), at("2030-01-01T00:00:00Z"), at("2019-01-01T00:00:00Z"), at("2020-12-31T23:59:59Z"), false},
		{"b starts after a", at("2020-01-01T00:00:00Z"), at("2021-01-01T00:00:00Z"), at("2021-01-01T00:00:01Z"), open, false},
		{"both open-ended", at("2020-01-01T00:00:00Z"), open, at("2025-01-01T00:00:00Z"), open, true},
		{"a open, b ends before a", at("2020-01-01T00:00:00Z"), open, at("2018-01-01T00:00:00Z"), at("2019-01-01T00:00:00Z"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := windowsOverlap(tc.aStart, tc.aEnd, tc.bStart, tc.bEnd); got != tc.want {
				t.Fatalf("windowsOverlap = %v, want %v", got, tc.want)
			}
		})
	}
}
