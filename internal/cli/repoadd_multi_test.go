package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// TestRepoAddSeveralDirsPublishesInOneBuild covers the per-platform release
// flow: every build of a version is registered by one `repo add`, published by
// one reconcile, and reported in the additive `added` list while the
// single-source `package`/`version` keys keep naming the first directory.
func TestRepoAddSeveralDirsPublishesInOneBuild(t *testing.T) {
	mPath, keyDir, env := setupHelloBuilds(t)
	repoDir := filepath.Dir(mPath)
	linux := writeHelloBuild(t, repoDir, helloBuild{"hello-linux-amd64", "1.0.0", "linux/amd64"})
	darwin := writeHelloBuild(t, repoDir, helloBuild{"hello-darwin-arm64", "1.0.0", "darwin/arm64"})

	out, err := runRepo(t, env, "--format", "json", "repo", "add", linux, darwin, "--manifest", mPath, "--key-dir", keyDir)
	if err != nil {
		t.Fatalf("repo add: %v (out=%s)", err, out)
	}
	res, err := schema.ParseCLIResult(strings.NewReader(out))
	if err != nil {
		t.Fatalf("parse cli result: %v (out=%s)", err, out)
	}
	if res.Data["package"] != "hello" || res.Data["version"] != "1.0.0" {
		t.Fatalf("package/version = %v/%v, want hello/1.0.0 (the first source)", res.Data["package"], res.Data["version"])
	}
	// One reconcile of a never-built repository publishes serial 1.
	if res.Data["serial"] != float64(1) {
		t.Fatalf("serial = %v, want 1 (both sources published by a single build)", res.Data["serial"])
	}
	added, ok := res.Data["added"].([]any)
	if !ok || len(added) != 2 {
		t.Fatalf("added = %#v, want two entries", res.Data["added"])
	}
	for i, want := range []map[string]any{
		{"package": "hello", "version": "1.0.0", "platform": "linux/amd64", "source": filepath.Join("pkgs", "hello-linux-amd64")},
		{"package": "hello", "version": "1.0.0", "platform": "darwin/arm64", "source": filepath.Join("pkgs", "hello-darwin-arm64")},
	} {
		got, _ := added[i].(map[string]any)
		for k, v := range want {
			if got[k] != v {
				t.Fatalf("added[%d][%s] = %v, want %v (entry %v)", i, k, got[k], v, got)
			}
		}
	}

	if got, want := manifestHelloSources(t, mPath), []string{
		filepath.Join("pkgs", "hello-linux-amd64"), filepath.Join("pkgs", "hello-darwin-arm64"),
	}; !slices.Equal(got, want) {
		t.Fatalf("manifest hello sources = %q, want %q", got, want)
	}
	if got := publishedHelloVersions(t, mPath); !slices.Equal(got, []string{"1.0.0", "1.0.0"}) {
		t.Fatalf("published hello versions = %q, want one entry per platform", got)
	}
	assertNoPendingChanges(t, mPath, keyDir)
}

func TestRepoAddTextOutput(t *testing.T) {
	mPath, keyDir, env := setupHelloBuilds(t)
	repoDir := filepath.Dir(mPath)

	one := writeHelloBuild(t, repoDir, helloBuild{"hello-1.0.0", "1.0.0", ""})
	out, err := runRepo(t, env, "repo", "add", one, "--manifest", mPath, "--key-dir", keyDir)
	if err != nil {
		t.Fatalf("repo add: %v (out=%s)", err, out)
	}
	if want := "Added hello@1.0.0 and rebuilt the repository (serial 1)\n"; out != want {
		t.Fatalf("single-source output = %q, want the unchanged one-line form %q", out, want)
	}

	linux := writeHelloBuild(t, repoDir, helloBuild{"hello-2.0.0-linux-amd64", "2.0.0", "linux/amd64"})
	darwin := writeHelloBuild(t, repoDir, helloBuild{"hello-2.0.0-darwin-arm64", "2.0.0", "darwin/arm64"})
	out, err = runRepo(t, env, "repo", "add", linux, darwin, "--manifest", mPath, "--key-dir", keyDir)
	if err != nil {
		t.Fatalf("repo add: %v (out=%s)", err, out)
	}
	want := "Added 2 package sources and rebuilt the repository (serial 2)\n" +
		"  hello@2.0.0 (linux/amd64)\n" +
		"  hello@2.0.0 (darwin/arm64)\n"
	if out != want {
		t.Fatalf("multi-source output = %q, want %q", out, want)
	}
}

// TestRepoAddSeveralDirsIsAllOrNothing extends the add invariant to a batch:
// one bad directory — unreadable up front, or failing while the repository
// builds — rejects every directory, leaves polypkg-repo.yaml byte-identical,
// and publishes nothing.
func TestRepoAddSeveralDirsIsAllOrNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  func(t *testing.T, repoDir string) string
		want string
	}{
		{"unreadable source", func(t *testing.T, _ string) string { return t.TempDir() }, "cannot read package source"},
		{"unbuildable source", func(t *testing.T, repoDir string) string {
			dir, _ := writeUnpackablePkgSource(t, repoDir)
			return dir
		}, "cannot pack package"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mPath, keyDir, env := setupHelloBuilds(t, helloBuild{"hello-1.0.0", "1.0.0", ""})
			repoDir := filepath.Dir(mPath)
			good := writeHelloBuild(t, repoDir, helloBuild{"hello-1.1.0", "1.1.0", ""})
			bad := tc.bad(t, repoDir)
			before := readManifestBytes(t, mPath)

			out, err := runRepo(t, env, "repo", "add", good, bad, "--manifest", mPath, "--key-dir", keyDir)
			if err == nil {
				t.Fatalf("expected the batch to fail, got success (out=%s)", out)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want %q", err, tc.want)
			}
			if after := readManifestBytes(t, mPath); !bytes.Equal(before, after) {
				t.Fatalf("a failed batch rewrote the manifest\nbefore:\n%s\nafter:\n%s", before, after)
			}
			if got := publishedHelloVersions(t, mPath); !slices.Equal(got, []string{"1.0.0"}) {
				t.Fatalf("published hello versions = %q, want only 1.0.0 (the good source must not publish alone)", got)
			}
			assertNoPendingChanges(t, mPath, keyDir)
		})
	}
}

// TestRepoAddRejectsTheSameDirTwice pins that a directory given twice, however
// it is spelled, is refused before the signing key is unlocked: the operator
// is not asked for (here: handed a wrong) key password for a batch that could
// never run.
func TestRepoAddRejectsTheSameDirTwice(t *testing.T) {
	for name, respell := range map[string]func(dir string) string{
		"trailing separator": func(dir string) string { return dir + string(os.PathSeparator) },
		"dot-dot detour": func(dir string) string {
			return filepath.Join(dir, "..", filepath.Base(dir)) + string(os.PathSeparator) + "."
		},
	} {
		t.Run(name, func(t *testing.T) {
			mPath, keyDir, env := setupHelloBuilds(t, helloBuild{"hello-1.0.0", "1.0.0", ""})
			dir := writeHelloBuild(t, filepath.Dir(mPath), helloBuild{"hello-1.1.0", "1.1.0", ""})
			before := readManifestBytes(t, mPath)
			env["POLYPKG_REPO_KEY_PASSWORD"] = "not-the-password"

			_, err := runRepo(t, env, "repo", "add", dir, respell(dir), "--manifest", mPath, "--key-dir", keyDir)
			var ce *CLIError
			if !errors.As(err, &ce) {
				t.Fatalf("error = %v (%T), want a *CLIError", err, err)
			}
			if !strings.Contains(ce.Msg, "more than once") {
				t.Fatalf("Msg = %q, want it to say the directory is given more than once (before the key is unlocked)", ce.Msg)
			}
			if after := readManifestBytes(t, mPath); !bytes.Equal(before, after) {
				t.Fatalf("a rejected `repo add` rewrote the manifest:\n%s", after)
			}
		})
	}
}

func TestRepoAddNeedsADirectory(t *testing.T) {
	mPath, keyDir, env := setupHelloBuilds(t)
	_, err := runRepo(t, env, "repo", "add", "--manifest", mPath, "--key-dir", keyDir)
	var ce *CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("error = %v (%T), want a *CLIError", err, err)
	}
	if !strings.Contains(ce.Msg, "needs at least one <package-source-dir>") {
		t.Fatalf("Msg = %q, want it to name the missing operand", ce.Msg)
	}
}
