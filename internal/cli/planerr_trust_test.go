package cli

import (
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/planner"
)

var _ = Describe("planExecError trust translation", func() {
	Describe("bad trust_root", func() {
		It("frames a path-aware CLIError with a .pub hint", func() {
			te := &planner.TrustRootError{
				Path: "/tmp/badkey.pub",
				Err:  errors.New("anchor is not a valid minisign public key"),
			}
			got := planExecError(fmt.Errorf("verify trust document: %w", te))
			var ce *CLIError
			Expect(errors.As(got, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", got, got)
			Expect(ce.Msg).To(Equal("trust_root /tmp/badkey.pub is not a valid minisign public key"))
			Expect(ce.Hint).To(ContainSubstring("trust_root must point at the repository's minisign .pub file"))
		})
	})

	Describe("tampered/invalid artifact signature", func() {
		It("frames a source-aware CLIError and does not leak the verify detail", func() {
			ase := &planner.ArtifactSignatureError{
				Name:    "hello",
				Version: "1.1.0",
				Source:  "native",
				Err:     errors.New("verify signature: Invalid signature"),
			}
			got := planExecError(fmt.Errorf("plan: %w", ase))
			var ce *CLIError
			Expect(errors.As(got, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", got, got)
			Expect(ce.Msg).To(Equal(`signature verification failed for hello-1.1.0 from source "native"`))
			Expect(ce.Msg).NotTo(ContainSubstring("Invalid signature"))
			Expect(ce.Hint).To(ContainSubstring("does not match its signature"))
			Expect(ce.Hint).To(ContainSubstring("contact the repository operator"))
		})
	})
})

var _ = Describe("planExecError artifact identity translation", func() {
	DescribeTable("frames a recipe/index disagreement as a publisher fault",
		func(field, got, want, wantMsg string) {
			aie := &planner.ArtifactIdentityError{
				Name: "hello", Version: "1.0.0", Source: "native",
				Field: field, Got: got, Want: want,
			}
			res := planExecError(aie)
			var ce *CLIError
			Expect(errors.As(res, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", res, res)
			Expect(ce.Msg).To(Equal(wantMsg))
			Expect(ce.Hint).To(ContainSubstring("does not match the index entry"))
			Expect(ce.Hint).To(ContainSubstring("nothing was installed"))
			Expect(ce.Hint).To(ContainSubstring("contact the repository operator"))
			var unwrapped *planner.ArtifactIdentityError
			Expect(errors.As(ce, &unwrapped)).To(BeTrue(), "the typed cause must stay in the chain")
		},
		Entry("name", "name", "other", "hello",
			`artifact for hello 1.0.0 from source "native" declares name "other", but the index lists "hello"`),
		Entry("version", "version", "1.0.1", "1.0.0",
			`artifact for hello 1.0.0 from source "native" declares version "1.0.1", but the index lists "1.0.0"`),
		Entry("platform", "platform", "linux/amd64", "any",
			`artifact for hello 1.0.0 from source "native" declares platform "linux/amd64", but the index lists "any"`),
	)

	It("still matches when the planner error is wrapped", func() {
		aie := &planner.ArtifactIdentityError{Name: "hello", Version: "1.0.0", Source: "native", Field: "name", Got: "other", Want: "hello"}
		var ce *CLIError
		Expect(errors.As(planExecError(fmt.Errorf("plan: %w", aie)), &ce)).To(BeTrue())
		Expect(ce.Msg).To(HavePrefix("artifact for hello 1.0.0"))
	})
})
