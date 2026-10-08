package mirror

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSourcesFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sources.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseSourcesFileReadsEntries(t *testing.T) {
	p := writeSourcesFile(t, `
- url: https://a.example/repo
  trust_root: a.pub
  packages: [foo, bar@1.2.0]
- url: https://b.example/repo
  trust_root: b.pub
  source_name: beta
  accept_expiry_until: "2030-01-01T00:00:00Z"
`)
	specs, err := ParseSourcesFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 {
		t.Fatalf("want 2 specs, got %d", len(specs))
	}
	if specs[0].URL != "https://a.example/repo" || specs[0].TrustRoot != "a.pub" {
		t.Fatalf("spec[0] = %+v", specs[0])
	}
	if len(specs[0].Packages) != 2 || specs[0].Packages[1] != "bar@1.2.0" {
		t.Fatalf("spec[0].Packages = %v", specs[0].Packages)
	}
	if specs[1].SourceName != "beta" || specs[1].AcceptExpiryUntil != "2030-01-01T00:00:00Z" {
		t.Fatalf("spec[1] = %+v", specs[1])
	}
}

func TestParseSourcesFileRejectsMissingURL(t *testing.T) {
	p := writeSourcesFile(t, "- trust_root: a.pub\n")
	if _, err := ParseSourcesFile(p); err == nil || !strings.Contains(err.Error(), "url is required") {
		t.Fatalf("want url-required error, got %v", err)
	}
}

func TestParseSourcesFileRejectsMissingTrustRoot(t *testing.T) {
	p := writeSourcesFile(t, "- url: https://a.example/repo\n")
	if _, err := ParseSourcesFile(p); err == nil || !strings.Contains(err.Error(), "trust_root is required") {
		t.Fatalf("want trust_root-required error, got %v", err)
	}
}

func TestParseSourcesFileRejectsUnknownKey(t *testing.T) {
	p := writeSourcesFile(t, "- url: https://a.example/repo\n  trust_root: a.pub\n  packagez: [foo]\n")
	if _, err := ParseSourcesFile(p); err == nil || !strings.Contains(err.Error(), "parse sources file") {
		t.Fatalf("want unknown-key rejection, got %v", err)
	}
}

func TestParseSourcesFileRejectsEmpty(t *testing.T) {
	p := writeSourcesFile(t, "[]\n")
	if _, err := ParseSourcesFile(p); err == nil || !strings.Contains(err.Error(), "no sources") {
		t.Fatalf("want empty-list error, got %v", err)
	}
}

func TestParseSourcesFileRedactsTheURLOfAnEntryMissingItsTrustRoot(t *testing.T) {
	p := writeSourcesFile(t, "- url: https://ghp_secret@a.example/repo\n")
	_, err := ParseSourcesFile(p)
	if err == nil || !strings.Contains(err.Error(), "trust_root is required") {
		t.Fatalf("want trust_root-required error, got %v", err)
	}
	if strings.Contains(err.Error(), "ghp_secret") {
		t.Fatalf("error leaks the URL token: %v", err)
	}
	if !strings.Contains(err.Error(), "https://xxxxx@a.example/repo") {
		t.Fatalf("error = %v, want the redacted URL", err)
	}
}
