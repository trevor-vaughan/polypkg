package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

var _ = Describe("apply attestation warnings", func() {
	It("prints the unattested warning to stderr under the default policy", func() {
		// Publish a real signed repo WITHOUT attestations (--skip-attestations
		// path) and apply against it with no attestation block in the profile:
		// the default warn policy must surface the unattested package on stderr
		// on the APPLY path too, not just plan (apply.go loops over
		// Result.AttestationWarnings identically).
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
			"packages:\n  hello:\n    source: ./pkgs/hello\n"
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
		cmd.SetArgs([]string{"apply", "--scope", "user", profilePath})
		Expect(cmd.Execute()).To(Succeed())

		Expect(out.String()).To(ContainSubstring("applied generation 1"))
		Expect(errBuf.String()).To(ContainSubstring("warning: package hello-1.0.0 is not attested"))
		Expect(out.String()).NotTo(ContainSubstring("not attested"),
			"warnings belong on stderr, not in the apply body")
	})

	It("prints an unsuppressible SECURITY warning when a source sets tier: off", func() {
		// Same scaffolding as above, but the profile source disables its
		// attestation gate (tier: off). The planner routes such packages onto
		// Result.AttestationGateDisabled; apply must surface an UNCONDITIONAL
		// SECURITY warning on stderr (the un-silenceable per-source kill switch,
		// threat G8) in addition to writing an audit event.
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
			"packages:\n  hello:\n    source: ./pkgs/hello\n"
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
			"    attestation:\n      tier: off\n" +
			"packages:\n  user:\n    hello:\n      version: \">=1.0.0\"\n"
		profilePath := filepath.Join(env, "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())

		cmd := NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		var out, errBuf bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errBuf)
		cmd.SetArgs([]string{"apply", "--scope", "user", profilePath})
		Expect(cmd.Execute()).To(Succeed())

		stderr := errBuf.String()
		Expect(stderr).To(ContainSubstring("SECURITY"))
		Expect(stderr).To(ContainSubstring("hello-1.0.0"))
		Expect(stderr).To(ContainSubstring("gate disabled"))

		// The gate-off audit event records the package and its source as
		// DISCRETE fields (not "hello-1.0.0 (source repo)" mashed into one),
		// so an audit consumer can filter on source without string surgery.
		auditData, rerr := os.ReadFile(filepath.Join(env, "state", "polypkg", "audit.log"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(auditData)).To(ContainSubstring(`"event":"attestation.gate_off"`))
		Expect(string(auditData)).To(ContainSubstring(`"package":"hello-1.0.0"`))
		Expect(string(auditData)).To(ContainSubstring(`"source":"repo"`))
	})

	It("emits a loud SECURITY line and a metadata.expiry_graced audit event under grace", func() {
		// Same scaffolding as the tier:off spec, but instead of disabling the
		// attestation gate, the profile sets accept_expiry_until on the source
		// and the consumer clock is jumped past the published index's expires:
		// apply must accept the stale-but-signed index under grace AND surface
		// an unsuppressible SECURITY line plus a metadata.expiry_graced audit
		// event (phase 2e-1, spec §10.9 E-3).
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
			"packages:\n  hello:\n    source: ./pkgs/hello\n"
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
			"    accept_expiry_until: \"2999-01-01T00:00:00Z\"\n" +
			"packages:\n  user:\n    hello:\n      version: \">=1.0.0\"\n"
		profilePath := filepath.Join(env, "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())

		restore := trust.SetTimeNowForTesting(func() time.Time {
			return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
		})
		defer restore()

		cmd := NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		var out, errBuf bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errBuf)
		cmd.SetArgs([]string{"apply", "--scope", "user", profilePath})
		Expect(cmd.Execute()).To(Succeed())

		stderr := errBuf.String()
		Expect(stderr).To(ContainSubstring("SECURITY"))
		Expect(stderr).To(ContainSubstring("expired"))
		Expect(stderr).To(ContainSubstring("grace until 2999-01-01T00:00:00Z"))

		auditData, rerr := os.ReadFile(filepath.Join(env, "state", "polypkg", "audit.log"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(auditData)).To(ContainSubstring(`"event":"metadata.expiry_graced"`))
		Expect(string(auditData)).To(ContainSubstring(`"source":"repo"`))
		Expect(string(auditData)).To(ContainSubstring(`"accept_expiry_until":"2999-01-01T00:00:00Z"`))
	})
})
