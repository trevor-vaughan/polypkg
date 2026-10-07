package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/repo"
)

var _ = Describe("pkg build", func() {
	It("packs a .tar.zst, prints the digest, and writes the att preview", func() {
		src := GinkgoT().TempDir()
		root := NewRootCmd()
		root.SetArgs([]string{"pkg", "init", "--name", "hello", "--version", "1.0.0", src})
		Expect(root.Execute()).To(Succeed())

		outDir := GinkgoT().TempDir()
		build := NewRootCmd()
		var out bytes.Buffer
		build.SetOut(&out)
		build.SetArgs([]string{"pkg", "build", "-o", outDir, src})
		Expect(build.Execute()).To(Succeed())

		artifactPath := filepath.Join(outDir, "hello-1.0.0.tar.zst")
		attPath := filepath.Join(outDir, "hello-1.0.0.att.json")
		Expect(artifactPath).To(BeAnExistingFile())
		Expect(attPath).To(BeAnExistingFile())
		Expect(out.String()).To(ContainSubstring("blake3:"))

		raw, err := os.ReadFile(attPath)
		Expect(err).ToNot(HaveOccurred())
		var st attest.Statement
		Expect(json.Unmarshal(raw, &st)).To(Succeed())

		artifact, err := os.ReadFile(artifactPath)
		Expect(err).ToNot(HaveOccurred())
		// The subject digest (bare hex) reconstructs to the artifact content hash.
		Expect("blake3:" + st.Subject[0].Digest["blake3"]).To(Equal(repo.ContentHash(artifact)))
		Expect(st.PredicateType).To(Equal(attest.PredicateTypeSARIF))
		Expect(st.Type).To(Equal("https://in-toto.io/Statement/v1"))

		// The .att.json is the exact JCS-canonical Statement bytes (deterministic).
		canonical, err := st.CanonicalJSON()
		Expect(err).ToNot(HaveOccurred())
		Expect(raw).To(Equal(canonical))
	})

	It("produces a byte-identical att.json across two independent builds", func() {
		// repo build's signed attestation depends on this: the author's preview is
		// exactly the statement the publisher signs, and two builds of the same
		// source must yield the same bytes to sign.
		src := GinkgoT().TempDir()
		initCmd := NewRootCmd()
		initCmd.SetArgs([]string{"pkg", "init", "--name", "hello", "--version", "1.0.0", src})
		Expect(initCmd.Execute()).To(Succeed())

		outA := GinkgoT().TempDir()
		buildA := NewRootCmd()
		buildA.SetArgs([]string{"pkg", "build", "-o", outA, src})
		Expect(buildA.Execute()).To(Succeed())

		outB := GinkgoT().TempDir()
		buildB := NewRootCmd()
		buildB.SetArgs([]string{"pkg", "build", "-o", outB, src})
		Expect(buildB.Execute()).To(Succeed())

		attA, err := os.ReadFile(filepath.Join(outA, "hello-1.0.0.att.json"))
		Expect(err).ToNot(HaveOccurred())
		attB, err := os.ReadFile(filepath.Join(outB, "hello-1.0.0.att.json"))
		Expect(err).ToNot(HaveOccurred())
		Expect(attA).To(Equal(attB))
	})

	It("creates a missing output directory before building", func() {
		src := GinkgoT().TempDir()
		root := NewRootCmd()
		root.SetArgs([]string{"pkg", "init", "--name", "hello", "--version", "1.0.0", src})
		Expect(root.Execute()).To(Succeed())

		outDir := filepath.Join(GinkgoT().TempDir(), "nested", "deep")
		build := NewRootCmd()
		build.SetArgs([]string{"pkg", "build", "-o", outDir, src})
		Expect(build.Execute()).To(Succeed())

		Expect(filepath.Join(outDir, "hello-1.0.0.tar.zst")).To(BeAnExistingFile())
		Expect(filepath.Join(outDir, "hello-1.0.0.att.json")).To(BeAnExistingFile())
	})

	It("fails fast when the output directory cannot be created", func() {
		src := GinkgoT().TempDir()
		root := NewRootCmd()
		root.SetArgs([]string{"pkg", "init", "--name", "hello", "--version", "1.0.0", src})
		Expect(root.Execute()).To(Succeed())

		// A path through an existing file can never become a directory.
		blocker := filepath.Join(GinkgoT().TempDir(), "x")
		Expect(os.WriteFile(blocker, []byte("not a dir"), 0o644)).To(Succeed())
		outDir := filepath.Join(blocker, "sub")

		build := NewRootCmd()
		build.SetErr(&bytes.Buffer{})
		build.SetArgs([]string{"pkg", "build", "-o", outDir, src})
		err := build.Execute()
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(Equal("cannot create output directory " + outDir + ": part of the path is not a directory"))
		Expect(ce.Hint).To(ContainSubstring("-o"))
		Expect(outDir).ToNot(BeADirectory())
	})

	It("names the artifact it cannot write and why", func() {
		src := GinkgoT().TempDir()
		root := NewRootCmd()
		root.SetOut(&bytes.Buffer{})
		root.SetArgs([]string{"pkg", "init", "--name", "hello", "--version", "1.0.0", src})
		Expect(root.Execute()).To(Succeed())
		outDir := filepath.Join(GinkgoT().TempDir(), "ro")
		Expect(os.Mkdir(outDir, 0o500)).To(Succeed())
		DeferCleanup(os.Chmod, outDir, os.FileMode(0o700))

		build := NewRootCmd()
		build.SetOut(&bytes.Buffer{})
		build.SetErr(&bytes.Buffer{})
		build.SetArgs([]string{"pkg", "build", "-o", outDir, src})
		err := build.Execute()

		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(Equal("cannot write artifact " + filepath.Join(outDir, "hello-1.0.0.tar.zst") + ": permission denied"))
		Expect(ce.Hint).To(ContainSubstring("-o"))
	})

	It("aborts on lint errors and writes nothing", func() {
		src := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(src, "polypkg.yaml"),
			[]byte("schema: polypkg.package/v1\nname: x\nversion: 1.0.0\nactions:\n  - phase: post-place\n    action: frobnicate\n    params: {}\n"),
			0o644)).To(Succeed())

		outDir := GinkgoT().TempDir()
		build := NewRootCmd()
		build.SetArgs([]string{"pkg", "build", "-o", outDir, src})
		Expect(build.Execute()).ToNot(Succeed())

		entries, err := os.ReadDir(outDir)
		Expect(err).ToNot(HaveOccurred())
		Expect(entries).To(BeEmpty())
	})
})

var _ = Describe("pkg build pack refusals", func() {
	DescribeTable("names the file that cannot be packed, why, and what to change",
		func(makeBad func(testing.TB, string) string, reason, wantHint string) {
			sandboxUserEnv(GinkgoTB())
			src := GinkgoT().TempDir()
			initCmd := NewRootCmd()
			initCmd.SetOut(&bytes.Buffer{})
			initCmd.SetArgs([]string{"pkg", "init", "--name", "hello", src})
			Expect(initCmd.Execute()).To(Succeed())
			rel := makeBad(GinkgoTB(), src)

			build := NewRootCmd()
			build.SetOut(&bytes.Buffer{})
			build.SetErr(&bytes.Buffer{})
			build.SetArgs([]string{"pkg", "build", "-o", GinkgoT().TempDir(), src})
			err := build.Execute()
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "want a CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring(fmt.Sprintf("%q", rel)))
			Expect(ce.Msg).To(ContainSubstring(reason))
			Expect(ce.Hint).To(ContainSubstring(wantHint))
		},
		Entry("a setuid file", makeSetuidContent, "is setuid", "chmod u-s,g-s,-t"),
		Entry("a path too deep to extract", makeTooDeepContent, "more than 64 path segments", "shorten"),
	)
})
