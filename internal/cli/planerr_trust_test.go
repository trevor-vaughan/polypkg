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
