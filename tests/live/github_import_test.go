// Package live holds opt-in tests that reach the real network. They skip
// unless POLYPKG_TEST_LIVE=1, which `task test:live` sets.
package live

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/cli"
	"github.com/trevor-vaughan/polypkg/internal/platform"
)

// TestLiveGitHubImport imports the latest GitHub CLI release with the
// Sigstore public-good root fetched over TUF, and requires the host
// platform's package to carry at least one verified attestation.
func TestLiveGitHubImport(t *testing.T) {
	if os.Getenv("POLYPKG_TEST_LIVE") != "1" {
		t.Skip("live network test: run `task test:live` (set GITHUB_TOKEN to avoid GitHub's anonymous rate limit)")
	}
	host := platform.Host()
	if host != "linux/amd64" && host != "linux/arm64" && host != "linux/386" &&
		host != "darwin/amd64" && host != "darwin/arm64" {
		t.Skipf("cli/cli publishes no %s archive", host)
	}

	sandbox := t.TempDir()
	for env, sub := range map[string]string{
		"HOME": "home", "XDG_CONFIG_HOME": "config", "XDG_DATA_HOME": "data",
		"XDG_STATE_HOME": "state", "XDG_CACHE_HOME": "cache",
	} {
		t.Setenv(env, filepath.Join(sandbox, sub))
	}
	out := filepath.Join(sandbox, "imports")

	root := cli.NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--format", "json", "pkg", "import", "github:cli/cli", out, "--name", "gh", "--bin", "gh"})
	if err := root.Execute(); err != nil {
		t.Fatalf("pkg import github:cli/cli: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}

	var env struct {
		Data struct {
			Version   string `json:"version"`
			Platforms []struct {
				Platform     string `json:"platform"`
				Integrity    string `json:"integrity"`
				Attestations int    `json:"attestations"`
			} `json:"platforms"`
		} `json:"data"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("decode result: %v\n%s", err, stdout.String())
	}
	for _, p := range env.Data.Platforms {
		if p.Platform != host {
			continue
		}
		if p.Integrity != "github-digest" && p.Integrity != "checksums-file" {
			t.Errorf("gh %s %s integrity = %q, want github-digest or checksums-file", env.Data.Version, host, p.Integrity)
		}
		if p.Attestations < 1 {
			t.Errorf("gh %s %s kept %d attestations, want at least 1", env.Data.Version, host, p.Attestations)
		}
		return
	}
	t.Fatalf("gh %s: no %s package imported; got %+v", env.Data.Version, host, env.Data.Platforms)
}
