package cli

import (
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("planExecError resolver translation", func() {
	It("translates an unknown-name ResolveError into a name-focused CLIError", func() {
		re := &resolver.ResolveError{
			Kind:        resolver.KindUnknownName,
			Requirement: resolver.Requirement{Name: "nosuchpkg", VersionRange: "=1.0.0"},
		}
		wrapped := fmt.Errorf("resolve: %w", re)
		got := planExecError(wrapped)
		var ce *CLIError
		Expect(errors.As(got, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", got, got)
		Expect(ce.Msg).To(Equal(`package "nosuchpkg" not found in any configured source`))
		Expect(ce.Hint).To(ContainSubstring("check the package name"))
		Expect(ce.Hint).To(ContainSubstring("sources in your profile"))
	})

	It("translates a no-version ResolveError into a version-focused CLIError with the available list", func() {
		re := &resolver.ResolveError{
			Kind:        resolver.KindNoVersion,
			Requirement: resolver.Requirement{Name: "hello", VersionRange: "=9.9.9"},
			Available:   []string{"1.1.0", "1.0.0"},
		}
		wrapped := fmt.Errorf("resolve: %w", re)
		got := planExecError(wrapped)
		var ce *CLIError
		Expect(errors.As(got, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", got, got)
		Expect(ce.Msg).To(Equal(`package "hello" has no version matching "=9.9.9" (available: 1.1.0, 1.0.0)`))
		Expect(ce.Hint).To(ContainSubstring("adjust the version constraint"))
	})

	It("preserves the transitive provenance suffix in the translated message", func() {
		re := &resolver.ResolveError{
			Kind:        resolver.KindNoVersion,
			Requirement: resolver.Requirement{Name: "lib", VersionRange: "=9.9.9"},
			Available:   []string{"2.0.0"},
			Path:        []string{"app", "lib"},
		}
		got := planExecError(fmt.Errorf("resolve: %w", re))
		var ce *CLIError
		Expect(errors.As(got, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("required via app -> lib"))
	})

	It("passes through errors with no recognized typed cause unchanged", func() {
		plain := errors.New("some other failure")
		Expect(planExecError(plain)).To(Equal(plain))
	})

	It("passes a nil error through as nil", func() {
		Expect(planExecError(nil)).To(BeNil())
	})
})

var _ = Describe("planExecError attestation translation", func() {
	const sarif = "https://polypkg.dev/attestation/sarif/v1"
	const slsa = "https://slsa.dev/provenance/v1"

	It("explains a source-change posture regression and offers a remedy other than pinning", func() {
		pfe := &planner.PostureFloorError{
			Predicate:    sarif,
			CurrentTier:  schema.CarriedTierBoundUnverified,
			NativeBefore: true,
		}
		got := planExecError(fmt.Errorf("provpkg-1.0.0: %w", pfe))
		var ce *CLIError
		Expect(errors.As(got, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", got, got)
		Expect(ce.Msg).To(ContainSubstring("provpkg-1.0.0"))
		Expect(ce.Msg).To(ContainSubstring("posture floor"))
		Expect(ce.Msg).To(ContainSubstring(sarif))
		Expect(ce.Hint).To(ContainSubstring("mirror pull"))
		Expect(ce.Hint).To(ContainSubstring("polypkg remove"))
		Expect(ce.Hint).To(ContainSubstring("pin the exact version"))
	})

	It("does not blame a mirror for a plain provenance regression", func() {
		pfe := &planner.PostureFloorError{Predicate: slsa}
		got := planExecError(fmt.Errorf("provpkg-1.0.0: %w", pfe))
		var ce *CLIError
		Expect(errors.As(got, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", got, got)
		Expect(ce.Hint).NotTo(ContainSubstring("mirror pull"))
		Expect(ce.Hint).To(ContainSubstring("pin the exact version"))
	})

	It("frames a revoked builder key as a revocation, not a missing predicate", func() {
		ape := &planner.AttestationPolicyError{
			Predicate:          slsa,
			RevokedBuilderKeys: []string{"builder-current"},
		}
		got := planExecError(fmt.Errorf("provpkg-1.0.0: %w", ape))
		var ce *CLIError
		Expect(errors.As(got, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", got, got)
		Expect(ce.Msg).To(ContainSubstring("revoke"))
		Expect(ce.Msg).To(ContainSubstring("builder-current"))
		Expect(ce.Hint).To(ContainSubstring("revoked"))
	})

	It("keeps the ordinary policy hint when no key was revoked", func() {
		ape := &planner.AttestationPolicyError{Predicate: slsa}
		got := planExecError(fmt.Errorf("provpkg-1.0.0: %w", ape))
		var ce *CLIError
		Expect(errors.As(got, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", got, got)
		Expect(ce.Msg).NotTo(ContainSubstring("revoke"))
		Expect(ce.Hint).To(ContainSubstring("attestation.require"))
	})
})
