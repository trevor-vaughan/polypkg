package mirror_test

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/mirror"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// buildBundle lays out a one-package repo, builds it, exports a whole-repo
// bundle, and returns (bundlePath, trustRootPath).
func buildBundle(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	keyDir := t.TempDir()
	pkgDir := filepath.Join(root, "pkgs", "hello", "content", "bin")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pkgs", "hello", "polypkg.yaml"),
		[]byte("schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "hello"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	kp, err := repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "example.key")
	if err := repo.SaveKey(keyPath, kp, "pw", repo.KDFScrypt); err != nil {
		t.Fatal(err)
	}
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	manifest := "schema: polypkg.repo/v1\nsource: example\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    - source: ./pkgs/hello\n"
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(repo.BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(t.TempDir(), "bundle.tar")
	b2, _ := repo.NewBuilder(mPath, keyDir, "pw")
	if _, err := b2.ExportBundle(nil, bundle); err != nil {
		t.Fatal(err)
	}
	return bundle, filepath.Join(root, "public", "trust_root.pub")
}

// rewriteTar reads a tar, applies mutate to the name->bytes map, and writes it back.
func rewriteTar(t *testing.T, src, dst string, mutate func(map[string][]byte)) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	files := map[string][]byte{}
	var order []string
	tr := tar.NewReader(in)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		files[hdr.Name] = b
		order = append(order, hdr.Name)
	}
	mutate(files)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	seen := map[string]bool{}
	emit := func(name string) {
		body, ok := files[name]
		if !ok || seen[name] {
			return
		}
		seen[name] = true
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Format: tar.FormatPAX})
		_, _ = tw.Write(body)
	}
	for _, n := range order {
		emit(n)
	}
	for n := range files {
		emit(n)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// appendTarMember rewrites src to dst, appending one extra member with the
// given typeflag/linkname (used to forge non-regular smuggled members).
func appendTarMember(t *testing.T, src, dst, name string, typeflag byte, linkname string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tr := tar.NewReader(in)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: typeflag, Linkname: linkname, Mode: 0o777, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyBundleRejectsSymlinkMember(t *testing.T) {
	bundle, root := buildBundle(t)
	bad := filepath.Join(t.TempDir(), "symlink.tar")
	appendTarMember(t, bundle, bad, "pool/evil", tar.TypeSymlink, "/etc/passwd")
	_, err := mirror.VerifyBundle(bad, mirror.VerifyOptions{TrustRootPath: root})
	if err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("want non-regular-member rejection, got %v", err)
	}
}

func TestVerifyBundleRejectsPathTraversal(t *testing.T) {
	bundle, root := buildBundle(t)
	bad := filepath.Join(t.TempDir(), "traverse.tar")
	appendTarMember(t, bundle, bad, "../escape", tar.TypeReg, "")
	_, err := mirror.VerifyBundle(bad, mirror.VerifyOptions{TrustRootPath: root})
	if err == nil || !strings.Contains(err.Error(), "unsafe path") {
		t.Fatalf("want unsafe-path rejection, got %v", err)
	}
}

func TestVerifyBundleRejectsDuplicatePath(t *testing.T) {
	bundle, root := buildBundle(t)
	bad := filepath.Join(t.TempDir(), "dup.tar")
	appendTarMember(t, bundle, bad, "index.json", tar.TypeReg, "")
	_, err := mirror.VerifyBundle(bad, mirror.VerifyOptions{TrustRootPath: root})
	if err == nil || !strings.Contains(err.Error(), "duplicate path") {
		t.Fatalf("want duplicate-path rejection, got %v", err)
	}
}

func TestVerifyBundleHappyPinnedRoot(t *testing.T) {
	bundle, root := buildBundle(t)
	res, err := mirror.VerifyBundle(bundle, mirror.VerifyOptions{TrustRootPath: root})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Source != "example" || res.EntriesChecked == 0 || res.Graced {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestVerifyBundleHappyEmbeddedRoot(t *testing.T) {
	bundle, _ := buildBundle(t)
	if _, err := mirror.VerifyBundle(bundle, mirror.VerifyOptions{}); err != nil {
		t.Fatalf("verify with embedded root: %v", err)
	}
}

func TestVerifyBundleTamperedBlobFails(t *testing.T) {
	bundle, root := buildBundle(t)
	bad := filepath.Join(t.TempDir(), "bad.tar")
	rewriteTar(t, bundle, bad, func(m map[string][]byte) {
		for n := range m {
			if strings.HasPrefix(n, "pool/") && strings.HasSuffix(n, ".tar.zst") {
				m[n] = append(m[n], 0x00)
				break
			}
		}
	})
	_, err := mirror.VerifyBundle(bad, mirror.VerifyOptions{TrustRootPath: root})
	if err == nil || !strings.Contains(err.Error(), "content hash mismatch") {
		t.Fatalf("want content-hash mismatch, got %v", err)
	}
}

func TestVerifyBundleMissingBlobFails(t *testing.T) {
	bundle, root := buildBundle(t)
	bad := filepath.Join(t.TempDir(), "missing.tar")
	rewriteTar(t, bundle, bad, func(m map[string][]byte) {
		for n := range m {
			if strings.HasPrefix(n, "pool/") && strings.HasSuffix(n, ".tar.zst") {
				delete(m, n)
				break
			}
		}
	})
	_, err := mirror.VerifyBundle(bad, mirror.VerifyOptions{TrustRootPath: root})
	if err == nil || !strings.Contains(err.Error(), "missing manifest entry") {
		t.Fatalf("want missing-entry error, got %v", err)
	}
}

func TestVerifyBundleSmuggledFileFails(t *testing.T) {
	bundle, root := buildBundle(t)
	bad := filepath.Join(t.TempDir(), "extra.tar")
	rewriteTar(t, bundle, bad, func(m map[string][]byte) {
		m["pool/deadbeef.tar.zst"] = []byte("smuggled")
	})
	_, err := mirror.VerifyBundle(bad, mirror.VerifyOptions{TrustRootPath: root})
	if err == nil || !strings.Contains(err.Error(), "not covered by the signed manifest") {
		t.Fatalf("want smuggled-file error, got %v", err)
	}
}

func TestVerifyBundleTamperedManifestFails(t *testing.T) {
	bundle, root := buildBundle(t)
	bad := filepath.Join(t.TempDir(), "badman.tar")
	rewriteTar(t, bundle, bad, func(m map[string][]byte) {
		m["pool-manifest.json"] = bytes.Replace(m["pool-manifest.json"], []byte("example"), []byte("evilorg"), 1)
	})
	_, err := mirror.VerifyBundle(bad, mirror.VerifyOptions{TrustRootPath: root})
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("want signature error, got %v", err)
	}
}

func TestVerifyBundleExpiryAndGrace(t *testing.T) {
	bundle, root := buildBundle(t)
	restore := trust.SetTimeNowForTesting(func() time.Time {
		return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	})
	defer restore()

	if _, err := mirror.VerifyBundle(bundle, mirror.VerifyOptions{TrustRootPath: root}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("want expiry refusal, got %v", err)
	}
	res, err := mirror.VerifyBundle(bundle, mirror.VerifyOptions{TrustRootPath: root, AcceptExpiryUntil: "2999-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("grace verify: %v", err)
	}
	if !res.Graced {
		t.Fatal("expected Graced=true within accept_expiry_until")
	}
}
