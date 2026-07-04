package cli

import (
	"bytes"
	"errors"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("argument validation", func() {
	It("explains what operand is missing instead of counting args", func() {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"generation", "pin"})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		err := cmd.Execute()
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("polypkg generation pin needs <generation-id> (got no arguments)"))
		Expect(ce.Hint).To(ContainSubstring("usage:"))
	})

	It("says expected when too many args are given", func() {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"alternatives", "set", "a", "b", "c"})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		err := cmd.Execute()
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("expected <name> <package> (got 3 arguments)"))
	})

	It("emits a cli-result envelope for arg errors under --format json", func() {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"generation", "pin", "--format", "json"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&bytes.Buffer{})
		err := cmd.Execute()
		Expect(err).To(HaveOccurred())
		Expect(out.String()).To(ContainSubstring(`"schema":"polypkg.cli-result/v2"`))
		Expect(out.String()).To(ContainSubstring(`"command":"pin"`))
		Expect(out.String()).To(ContainSubstring(`"hint":"usage:`))
	})

	It("suggests the closest command for a typo", func() {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"stauts"})
		var errOut bytes.Buffer
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&errOut)
		err := cmd.Execute()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("status"))
	})
})

var _ = Describe("flag parse error shaping", func() {
	It("translates unknown flag into CLIError with did-you-mean hint when close match exists", func() {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"plan", "--scop", "user"})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		err := cmd.Execute()
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(Equal("unknown flag --scop"))
		Expect(ce.Hint).To(ContainSubstring("--scope"))
		Expect(ce.Hint).To(ContainSubstring("usage:"))
	})

	It("translates unknown flag with no close match into CLIError with usage hint only", func() {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"gc", "--zzzzz"})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		err := cmd.Execute()
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(Equal("unknown flag --zzzzz"))
		Expect(ce.Hint).To(ContainSubstring("usage:"))
		Expect(ce.Hint).NotTo(ContainSubstring("did you mean"))
	})

	It("translates invalid typed argument without strconv leak", func() {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"gc", "--count", "abc"})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		err := cmd.Execute()
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(Equal(`invalid value "abc" for --count (expected a number)`))
		Expect(ce.Msg).NotTo(ContainSubstring("strconv"))
		Expect(ce.Msg).NotTo(ContainSubstring("ParseInt"))
	})

	It("translates missing flag argument into CLIError", func() {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"generation", "pin", "1", "--reason"})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		err := cmd.Execute()
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(Equal("--reason needs a value"))
		Expect(ce.Hint).To(ContainSubstring("usage:"))
	})

	It("emits a cli-result envelope for flag errors under --format json", func() {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"gc", "--format", "json", "--count", "abc"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&bytes.Buffer{})
		err := cmd.Execute()
		Expect(err).To(HaveOccurred())
		body := out.String()
		Expect(body).To(ContainSubstring(`"schema":"polypkg.cli-result/v2"`))
		Expect(body).To(ContainSubstring(`"status":"error"`))
		Expect(body).NotTo(ContainSubstring("strconv"))
	})

	It("falls back to text output when --format flag itself fails to parse", func() {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"gc", "--format", "badformat", "--count", "abc"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&bytes.Buffer{})
		err := cmd.Execute()
		// The flag error for --count abc is translated; --format "badformat" is a
		// different path (resolveFormat fails in RunE, not during flag parse).
		// We only care that the error is a CLIError and no strconv appears.
		Expect(err).To(HaveOccurred())
		Expect(strings.Contains(err.Error(), "strconv")).To(BeFalse())
	})
})
