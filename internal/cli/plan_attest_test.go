package cli

import (
	"bytes"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/repo"
)

var _ = Describe("plan attestation warnings", func() {
	It("prints the unattested warning to stderr under the default policy", func() {
		// Publish a real signed repo WITHOUT attestations (--skip-attestations
		// path) and plan against it with no attestation block in the profile:
		// the default warn policy must surface the unattested package on stderr.
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
		publicDir := filepath.Join(root, "public")

		env := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(env, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(env, "state"))
		GinkgoT().Setenv("XDG_CONFIG_HOME", filepath.Join(env, "config"))

		profile := "schema: polypkg.spec/v1\nname: att\n" +
			"scopes:\n  user:\n    substrate: store\n" +
			"sources:\n  order: [repo]\n  repo:\n    type: polypkg-native\n" +
			"    url: file://" + publicDir + "\n" +
			"    trust_root: " + filepath.Join(publicDir, "trust_root.pub") + "\n" +
			"packages:\n  user:\n    hello:\n      version: \">=1.0.0\"\n"
		profilePath := filepath.Join(env, "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())

		cmd := NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		var out, errBuf bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errBuf)
		cmd.SetArgs([]string{"plan", "--scope", "user", profilePath})
		// First plan against an empty state has changes pending (exit-2
		// sentinel), which Execute surfaces as an error; the warning must be on
		// stderr regardless.
		_ = cmd.Execute()

		Expect(errBuf.String()).To(ContainSubstring("warning: package hello-1.0.0 is not attested"))
		Expect(out.String()).NotTo(ContainSubstring("not attested"),
			"warnings belong on stderr, not in the plan body")
	})
})
