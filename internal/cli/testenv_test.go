package cli

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/repo"
)

// sandboxUserEnv points HOME, every XDG base directory polypkg reads, and the
// XDG search paths at a fresh temp tree, so an in-process command can never
// touch the invoking user's real state. It returns the tree's root; polypkg's
// user-scope dirs are <root>/{data,state,config}/polypkg. It takes a
// testing.TB so plain tests and Ginkgo specs (GinkgoTB()) share it.
func sandboxUserEnv(t testing.TB) string {
	t.Helper()
	root := t.TempDir()
	for env, sub := range map[string]string{
		"HOME":            "home",
		"XDG_CONFIG_HOME": "config",
		"XDG_DATA_HOME":   "data",
		"XDG_STATE_HOME":  "state",
		"XDG_CACHE_HOME":  "cache",
		"XDG_BIN_HOME":    "bin",
		"XDG_RUNTIME_DIR": "runtime",
		"XDG_CONFIG_DIRS": "config-dirs",
		"XDG_DATA_DIRS":   "data-dirs",
	} {
		t.Setenv(env, filepath.Join(root, sub))
	}
	return root
}

// publishUnattestedHello builds a real signed repository publishing
// hello-1.0.0 without attestations and returns its public directory, which a
// profile can name as a file:// source.
func publishUnattestedHello() string {
	GinkgoHelper()
	root := GinkgoT().TempDir()
	keyDir := GinkgoT().TempDir()

	pkgDir := filepath.Join(root, "pkgs", "hello")
	Expect(os.MkdirAll(filepath.Join(pkgDir, "content", "bin"), 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(pkgDir, "polypkg.yaml"),
		[]byte("schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"), 0o644)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(pkgDir, "content", "bin", "hello"),
		[]byte("#!/bin/sh\necho hi\n"), 0o755)).To(Succeed())

	kp, err := repo.GenerateKeypair()
	Expect(err).NotTo(HaveOccurred())
	keyPath := filepath.Join(keyDir, "repo.key")
	Expect(repo.SaveKey(keyPath, kp, "pw", repo.KDFScrypt)).To(Succeed())

	mPath := filepath.Join(root, "polypkg-repo.yaml")
	manifest := "schema: polypkg.repo/v1\nsource: repo\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    - source: ./pkgs/hello\n"
	Expect(os.WriteFile(mPath, []byte(manifest), 0o644)).To(Succeed())

	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	Expect(err).NotTo(HaveOccurred())
	_, err = b.Build(repo.BuildOptions{SkipAttestations: true})
	Expect(err).NotTo(HaveOccurred())
	return filepath.Join(root, "public")
}

// writeHelloProfile writes a user-scope profile requiring hello from the
// file:// repository at publicDir into dir and returns the profile's path.
// sourceExtra is appended verbatim to the repo source's block; each line must
// carry the source's four-space indent ("" adds nothing).
func writeHelloProfile(dir, publicDir, sourceExtra string) string {
	GinkgoHelper()
	profile := "schema: polypkg.spec/v1\nname: att\n" +
		"scopes:\n  user:\n    substrate: store\n" +
		"sources:\n  order: [repo]\n  repo:\n    type: polypkg-native\n" +
		"    url: file://" + publicDir + "\n" +
		"    trust_root: " + filepath.Join(publicDir, "trust_root.pub") + "\n" +
		sourceExtra +
		"packages:\n  user:\n    hello:\n      version: \">=1.0.0\"\n"
	profilePath := filepath.Join(dir, "profile.yaml")
	Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())
	return profilePath
}
