package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func TestRepoRevokePublishesSignedList(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")

	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}

	hash := "blake3:" + strings.Repeat("ab", 32)
	out, err := runRepo(t, env, "repo", "revoke", "--attestation", hash, "--manifest", mPath, "--key-dir", keyDir)
	if err != nil {
		t.Fatalf("repo revoke: %v (out=%s)", err, out)
	}

	pub := filepath.Join(repoDir, "public")
	raw, err := os.ReadFile(filepath.Join(pub, "revocations.json"))
	if err != nil {
		t.Fatalf("revocations.json missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(pub, "revocations.json.minisig")); err != nil {
		t.Fatalf("revocations.json.minisig missing: %v", err)
	}
	rl, err := schema.ParseRevocationList(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("emitted list fails schema parse: %v", err)
	}
	if len(rl.RevokedAttestations) != 1 || rl.RevokedAttestations[0] != hash {
		t.Fatalf("revoked_attestations = %v, want [%s]", rl.RevokedAttestations, hash)
	}
}

func TestRepoRevokeNeedsPassword(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")
	// Init via a password FILE so the environment stays clean — a leaked
	// POLYPKG_REPO_KEY_PASSWORD would mask the very failure this test asserts.
	pwFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwFile, []byte("pw"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runRepo(t, nil, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir, "--key-password-file", pwFile); err != nil {
		t.Fatalf("init: %v", err)
	}
	// No password source for revoke: it must fail rather than sign silently.
	hash := "blake3:" + strings.Repeat("ab", 32)
	if _, err := runRepo(t, nil, "repo", "revoke", "--attestation", hash, "--manifest", mPath, "--key-dir", keyDir); err == nil {
		t.Fatal("repo revoke without a signing-key password must error")
	}
}

func TestRepoRevokeRejectsNoTargets(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "r")
	keyDir := t.TempDir()
	env := map[string]string{"POLYPKG_REPO_KEY_PASSWORD": "pw"}
	mPath := filepath.Join(repoDir, "polypkg-repo.yaml")
	if _, err := runRepo(t, env, "repo", "init", repoDir, "--source", "example", "--key-dir", keyDir); err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := runRepo(t, env, "repo", "revoke", "--manifest", mPath, "--key-dir", keyDir); err == nil {
		t.Fatal("repo revoke with no --attestation/--builder-key must error")
	}
}
