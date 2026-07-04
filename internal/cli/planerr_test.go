package cli

import (
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/resolver"
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
