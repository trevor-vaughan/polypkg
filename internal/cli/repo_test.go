package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// publishedArtifactPath returns the on-disk path of pkg's published artifact by
// reading it from pubDir/index.json (artifacts are content-addressed under
// pool/, so the name cannot be predicted from name+version).
func publishedArtifactPath(t *testing.T, pubDir, pkg string) string {
	t.Helper()
	f, err := os.Open(filepath.Join(pubDir, "index.json"))
	if err != nil {
		t.Fatalf("open index.json: %v", err)
	}
	defer f.Close()
	idx, err := schema.ParseIndex(f)
	if err != nil {
		t.Fatalf("parse index.json: %v", err)
	}
	entries := idx.Packages[pkg]
	if len(entries) == 0 {
		t.Fatalf("package %q not in index", pkg)
	}
	return filepath.Join(pubDir, entries[0].Artifact)
}

// runRepo runs the root command in-process with args, capturing combined output.
func runRepo(t *testing.T, env map[string]string, args ...string) (string, error) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
	root := NewRootCmd()
	root.SilenceUsage, root.SilenceErrors = true, true
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestRepoInitCreatesManifest(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	out, err := runRepo(t,
		map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"},
		"repo", "init", repoDir, "--source", "example", "--key-dir", keyDir)
	if err != nil {
		t.Fatalf("repo init: %v (out=%s)", err, out)
	}
	if _, err := os.Stat(filepath.Join(repoDir, "polypkg-repo.yaml")); err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
}

func TestRepoInitNeedsPassword(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	// No password env, no --key-password-file.
	_, err := runRepo(t, nil, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir)
	if err == nil {
		t.Fatal("expected error when no password source is available")
	}
	var ce *CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *CLIError, got %T: %v", err, err)
	}
	if !strings.Contains(ce.Hint, "POLYPKG_REPO_KEY_PASSWORD") && !strings.Contains(ce.Hint, "key-password-file") {
		t.Fatalf("CLIError.Hint should mention POLYPKG_REPO_KEY_PASSWORD or key-password-file, got: %q", ce.Hint)
	}
}

func TestRepoInitPasswordFromFile(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	pwFile := filepath.Join(t.TempDir(), "pw.txt")
	if err := os.WriteFile(pwFile, []byte("filepw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runRepo(t, nil, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir, "--key-password-file", pwFile)
	if err != nil {
		t.Fatalf("repo init with password file: %v", err)
	}
}
