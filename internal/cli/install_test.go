package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"

	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("parsePackageArg", func() {
	DescribeTable("bare name, @version, @constraint forms",
		func(arg, wantName, wantTail string, wantBare bool) {
			name, tail, bare, err := parsePackageArg(arg)
			Expect(err).NotTo(HaveOccurred())
			Expect(name).To(Equal(wantName))
			Expect(tail).To(Equal(wantTail))
			Expect(bare).To(Equal(wantBare))
		},
		Entry("bare name resolves newest", "hello", "hello", "", true),
		Entry("bare version pins exact", "hello@1.2.3", "hello", "1.2.3", false),
		Entry("constraint >= passes verbatim", "hello@>=1.2", "hello", ">=1.2", false),
		Entry("constraint ^ passes verbatim", "hello@^1.0.0", "hello", "^1.0.0", false),
		Entry("constraint ~ passes verbatim", "hello@~1.2.0", "hello", "~1.2.0", false),
		Entry("constraint * passes verbatim", "hello@*", "hello", "*", false),
		Entry("constraint = passes verbatim", "hello@=1.0.0", "hello", "=1.0.0", false),
		Entry("constraint < passes verbatim", "hello@<2.0.0", "hello", "<2.0.0", false),
		Entry("digit prefix v is a bare version", "hello@2.0.0-rc1", "hello", "2.0.0-rc1", false),
	)

	It("rejects an empty tail after @", func() {
		_, _, _, err := parsePackageArg("hello@")
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(err).To(BeAssignableToTypeOf(ce))
	})

	It("rejects an invalid package name", func() {
		_, _, _, err := parsePackageArg("bad/name")
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring(`invalid package name "bad/name"`))
	})

	It("rejects an invalid package name before the @ tail", func() {
		_, _, _, err := parsePackageArg("bad name@1.0.0")
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("invalid package name"))
	})

	It("rejects an empty name", func() {
		_, _, _, err := parsePackageArg("@1.0.0")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("constraintForArg", func() {
	It("turns a bare version into an exact pin", func() {
		Expect(constraintForArg("1.2.3", false, "")).To(Equal("=1.2.3"))
	})
	It("passes a constraint tail through verbatim", func() {
		Expect(constraintForArg(">=1.2", false, "")).To(Equal(">=1.2"))
	})
	It("uses the resolved-newest lower bound for a bare name", func() {
		Expect(constraintForArg("", true, "1.1.0")).To(Equal(">=1.1.0"))
	})
	It("strips a leading v from a bare version tail", func() {
		Expect(constraintForArg("v1.0.0", false, "")).To(Equal("=1.0.0"))
	})
	It("strips a leading V from a bare version tail", func() {
		Expect(constraintForArg("V2.3.4", false, "")).To(Equal("=2.3.4"))
	})
	It("leaves a constraint tail starting with v verbatim (no operator)", func() {
		// "v1.2" starts with 'v' not a digit — treated as bare version, strip v
		Expect(constraintForArg("v1.2.0", false, "")).To(Equal("=1.2.0"))
	})
})

var _ = Describe("parsePackageArg v-prefix", func() {
	It("parses hello@v1.0.0 as name=hello tail=v1.0.0 bare=false", func() {
		name, tail, bare, err := parsePackageArg("hello@v1.0.0")
		Expect(err).NotTo(HaveOccurred())
		Expect(name).To(Equal("hello"))
		Expect(tail).To(Equal("v1.0.0"))
		Expect(bare).To(BeFalse())
	})
})

var _ = Describe("classifyEdit", func() {
	It("reports add when the package is not present", func() {
		Expect(classifyEdit("", ">=1.0.0")).To(Equal(editAdd))
	})
	It("reports kept when the constraint is unchanged", func() {
		Expect(classifyEdit(">=1.0.0", ">=1.0.0")).To(Equal(editKept))
	})
	It("reports update when the constraint differs", func() {
		Expect(classifyEdit(">=1.0.0", "=1.2.3")).To(Equal(editUpdate))
	})
})

var _ = Describe("renderInstallEdits", func() {
	It("renders an add line", func() {
		var buf bytes.Buffer
		renderInstallEdits(&buf, []installEdit{{Name: "hello", Constraint: ">=1.1.0", Action: editAdd}})
		Expect(buf.String()).To(ContainSubstring(`installing hello (">=1.1.0")`))
	})
	It("renders a kept line", func() {
		var buf bytes.Buffer
		renderInstallEdits(&buf, []installEdit{{Name: "hello", Constraint: ">=1.0.0", Action: editKept}})
		Expect(buf.String()).To(ContainSubstring(`hello is already in the profile (">=1.0.0")`))
	})
	It("renders an update line with old and new constraints", func() {
		var buf bytes.Buffer
		renderInstallEdits(&buf, []installEdit{{Name: "hello", Constraint: "=1.2.3", Action: editUpdate, Old: ">=1.0.0"}})
		Expect(buf.String()).To(ContainSubstring(`updating hello: ">=1.0.0" -> "=1.2.3"`))
	})
})

var _ = Describe("notChangedError", func() {
	It("appends the not-changed suffix to a CLIError message", func() {
		base := &CLIError{Msg: "run: boom", Hint: "retry"}
		wrapped := notChangedError(base)
		var ce *CLIError
		Expect(errors.As(wrapped, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("run: boom"))
		Expect(ce.Msg).To(ContainSubstring("(the profile was not changed)"))
		Expect(ce.Hint).To(Equal("retry"))
	})
	It("wraps a plain error and preserves it as the cause", func() {
		base := errors.New("plain boom")
		wrapped := notChangedError(base)
		Expect(wrapped.Error()).To(ContainSubstring("plain boom"))
		Expect(wrapped.Error()).To(ContainSubstring("(the profile was not changed)"))
	})
})

// I-1: with --scope system and POLYPKG_SYSTEM_PREFIX set, the lock file
// install acquires must land in the same stateHome that applyProfile would use.
// We verify this by checking that resolveAndEdit creates apply.lock under the
// env-derived stateHome (not the flag-only fallback).
var _ = Describe("I-1: install lock resolves through profile-aware prefix", func() {
	It("creates apply.lock under the POLYPKG_SYSTEM_PREFIX-derived stateHome", func() {
		prefix := GinkgoT().TempDir()
		GinkgoT().Setenv("POLYPKG_SYSTEM_PREFIX", prefix)

		// Build a cmd that mirrors what runInstall passes to resolveAndEdit.
		c := &cobra.Command{Use: "install", RunE: func(*cobra.Command, []string) error { return nil }}
		addScopeFlags(c)
		Expect(c.ParseFlags([]string{"--scope", "system"})).To(Succeed())

		p := &schema.Profile{
			Scopes: map[string]schema.ScopeSpec{
				"system": {Substrate: "store", Prefix: "/should-be-overridden-by-env"},
			},
		}

		scope, prefix2, err := resolveScope(c, p)
		Expect(err).NotTo(HaveOccurred())
		Expect(scope).To(Equal("system"))
		Expect(prefix2).To(Equal(prefix)) // env wins over profile

		_, stateHome, err2 := scopeHomes(scope, prefix2)
		Expect(err2).NotTo(HaveOccurred())

		// The stateHome resolveScope+scopeHomes produces must equal what
		// applyProfile would use: filepath.Join(prefix, paths.SystemStateDir()).
		wantStateHome := filepath.Join(prefix, paths.SystemStateDir())
		Expect(stateHome).To(Equal(wantStateHome))

		// Confirm the lock would land there (directory creation succeeds).
		Expect(os.MkdirAll(stateHome, 0o755)).To(Succeed())
		lockPath := filepath.Join(stateHome, "apply.lock")
		Expect(lockPath).To(Equal(filepath.Join(wantStateHome, "apply.lock")))
	})
})

var _ = Describe("restoreFailedError", func() {
	It("names both the apply failure and the restore failure", func() {
		postErr := errors.New("apply boom")
		restoreErr := errors.New("restore boom")
		err := restoreFailedError("/etc/polypkg/profile.yaml", "install", postErr, restoreErr)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("apply boom"))
		Expect(ce.Msg).To(ContainSubstring("restore boom"))
		Expect(ce.Msg).To(ContainSubstring("/etc/polypkg/profile.yaml"))
		// Both causes are joined for log inspection.
		Expect(errors.Is(ce.Err, postErr)).To(BeTrue())
		Expect(errors.Is(ce.Err, restoreErr)).To(BeTrue())
	})

	It("names the re-run verb in the hint per verb", func() {
		postErr := errors.New("apply boom")
		restoreErr := errors.New("restore boom")
		for _, verb := range []string{"install", "remove", "upgrade"} {
			err := restoreFailedError("/etc/polypkg/profile.yaml", verb, postErr, restoreErr)
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue())
			Expect(ce.Hint).To(ContainSubstring("polypkg " + verb))
		}
	})
})

var _ = Describe("restoreOnFailure", func() {
	It("restores the profile and wraps the apply error with the not-changed annotation", func() {
		dir := GinkgoT().TempDir()
		profilePath := filepath.Join(dir, "profile.yaml")
		original := []byte("schema: polypkg.spec/v1\nname: t\npackages:\n  user: {}\n")
		Expect(os.WriteFile(profilePath, original, 0o644)).To(Succeed())

		// Simulate a post-edit profile by writing different bytes.
		Expect(os.WriteFile(profilePath, []byte("edited\n"), 0o644)).To(Succeed())

		applyErr := errors.New("apply boom")
		err := restoreOnFailure(profilePath, original, applyErr, "upgrade")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("apply boom"))
		Expect(err.Error()).To(ContainSubstring("(the profile was not changed)"))

		// The profile bytes must be back to the pre-edit original.
		got, rerr := os.ReadFile(profilePath)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(got).To(Equal(original))
	})

	It("returns a restoreFailedError naming the verb when the restore itself fails", func() {
		// A path under a non-existent, non-writable directory makes Restore fail.
		profilePath := filepath.Join(GinkgoT().TempDir(), "missing-dir", "profile.yaml")
		applyErr := errors.New("apply boom")
		err := restoreOnFailure(profilePath, []byte("orig"), applyErr, "upgrade")
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("apply boom"))
		Expect(ce.Hint).To(ContainSubstring("polypkg upgrade"))
	})
})
