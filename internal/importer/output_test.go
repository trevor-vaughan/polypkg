package importer

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// snapshot records every path under dir with its type and, for files, mode and
// content, so a test can prove a tree is unchanged. A missing dir is nil.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			out[rel] = "symlink " + target
		case d.IsDir():
			out[rel] = "dir"
		default:
			info, err := d.Info()
			if err != nil {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[rel] = fmt.Sprintf("file %v %q", info.Mode().Perm(), b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// assertFile fails unless path is a regular file holding data with exactly mode.
func assertFile(t *testing.T, path string, data []byte, mode fs.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		t.Fatalf("%s: mode %v, want a regular file with %v", path, info.Mode(), mode)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("%s holds %q, want %q", path, got, data)
	}
}

// writeTree creates files (slash path → content) under dir.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for p, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func stageTool(t *testing.T, o *output, target string) string {
	t.Helper()
	dir, err := o.stage(target, []byte("schema: polypkg.package/v1\n"), "tool-linux-amd64", elfBinary, 0o755,
		[][]byte{[]byte(`{"n":1}`), []byte(`{"n":2}`)})
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestOutputCommitsIntoANewOutDir(t *testing.T) {
	out := filepath.Join(t.TempDir(), "imports")
	o, err := openOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	staged := stageTool(t, o, "tool/1.2.3/linux-amd64")
	if !strings.HasPrefix(staged, filepath.Join(out, stagingPrefix)) {
		t.Fatalf("staged at %s, want a path inside %s", staged, filepath.Join(out, stagingPrefix))
	}
	assertFile(t, filepath.Join(staged, "polypkg.yaml"), []byte("schema: polypkg.package/v1\n"), 0o644)
	if err := o.commit([]string{"tool/1.2.3/linux-amd64"}, []byte("root")); err != nil {
		t.Fatal(err)
	}
	if err := o.close(); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(out, "tool", "1.2.3", "linux-amd64")
	assertFile(t, filepath.Join(dir, "polypkg.yaml"), []byte("schema: polypkg.package/v1\n"), 0o644)
	assertFile(t, filepath.Join(dir, "content", "tool-linux-amd64"), elfBinary, 0o755)
	assertFile(t, filepath.Join(dir, "attestations", "1.json"), []byte(`{"n":1}`), 0o644)
	assertFile(t, filepath.Join(dir, "attestations", "2.json"), []byte(`{"n":2}`), 0o644)
	assertFile(t, filepath.Join(out, "sigstore-trusted-root.json"), []byte("root"), 0o644)
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !reflect.DeepEqual(names, []string{"sigstore-trusted-root.json", "tool"}) {
		t.Fatalf("out-dir holds %q, want only the trusted root and the package (no staging directory)", names)
	}
}

func TestOutputCommitKeepsOtherSourcesAndReplacesTheTrustedRoot(t *testing.T) {
	out := t.TempDir()
	writeTree(t, out, map[string]string{
		"other/1.0.0/linux-amd64/polypkg.yaml": "other",
		"sigstore-trusted-root.json":           "old root",
	})
	o, err := openOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	stageTool(t, o, "tool/1.2.3/linux-amd64")
	if err := o.commit([]string{"tool/1.2.3/linux-amd64"}, []byte("new root")); err != nil {
		t.Fatal(err)
	}
	if err := o.close(); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(out, "other", "1.0.0", "linux-amd64", "polypkg.yaml"), []byte("other"), 0o644)
	assertFile(t, filepath.Join(out, "sigstore-trusted-root.json"), []byte("new root"), 0o644)
}

func TestOutputCommitRefusesAnExistingTargetAndUndoesEverything(t *testing.T) {
	out := t.TempDir()
	writeTree(t, out, map[string]string{"other/polypkg.yaml": "other", "sigstore-trusted-root.json": "old root"})
	before := snapshot(t, out)
	o, err := openOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	stageTool(t, o, "tool/1.2.3/linux-amd64")
	// The first target moves in (creating tool/ and tool/1.2.3/) before the
	// second, which already exists, is refused.
	err = o.commit([]string{"tool/1.2.3/linux-amd64", "other"}, []byte("new root"))
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("commit error = %v, want an already-exists refusal", err)
	}
	if err := o.discard(); err != nil {
		t.Fatal(err)
	}
	if after := snapshot(t, out); !reflect.DeepEqual(after, before) {
		t.Fatalf("out-dir changed:\nbefore %v\nafter  %v", before, after)
	}
}

func TestOutputDiscardRemovesTheOutDirItCreated(t *testing.T) {
	out := filepath.Join(t.TempDir(), "imports")
	o, err := openOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	stageTool(t, o, "tool/1.2.3/linux-amd64")
	if err := o.discard(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(out); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("out-dir after discard: %v, want it gone", err)
	}
}

func TestOutputDiscardLeavesAnExistingOutDirAsItWas(t *testing.T) {
	out := t.TempDir()
	writeTree(t, out, map[string]string{"other/polypkg.yaml": "other"})
	before := snapshot(t, out)
	o, err := openOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	stageTool(t, o, "tool/1.2.3/linux-amd64")
	if err := o.discard(); err != nil {
		t.Fatal(err)
	}
	if after := snapshot(t, out); !reflect.DeepEqual(after, before) {
		t.Fatalf("out-dir changed:\nbefore %v\nafter  %v", before, after)
	}
}

func TestOutputCommitStaysInsideOutDir(t *testing.T) {
	outside := t.TempDir()
	out := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(out, "tool")); err != nil {
		t.Fatal(err)
	}
	o, err := openOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	stageTool(t, o, "tool/1.2.3/linux-amd64")
	if err := o.commit([]string{"tool/1.2.3/linux-amd64"}, []byte("root")); err == nil {
		t.Fatal("commit through a symlink out of out-dir succeeded")
	}
	if err := o.discard(); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("outside directory holds %v (err %v), want nothing", entries, err)
	}
}

func TestOpenOutputNeedsTheParentDirectory(t *testing.T) {
	if _, err := openOutput(filepath.Join(t.TempDir(), "missing", "imports")); err == nil {
		t.Fatal("openOutput created an out-dir whose parent does not exist")
	}
}
