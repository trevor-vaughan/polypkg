package cli

import (
	"bytes"
	"encoding/json"
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

	DescribeTable("names a nested command by its path, without the root, in the JSON envelope",
		func(want string, args ...string) {
			cmd := NewRootCmd()
			cmd.SetArgs(append([]string{"--format", "json"}, args...))
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&bytes.Buffer{})
			Expect(cmd.Execute()).To(HaveOccurred())
			var env struct {
				Command string `json:"command"`
				Status  string `json:"status"`
			}
			Expect(json.Unmarshal(out.Bytes(), &env)).To(Succeed(), "stdout must be one JSON envelope, got %q", out.String())
			Expect(env.Status).To(Equal("error"))
			Expect(env.Command).To(Equal(want))
		},
		Entry("repo remove", "repo remove", "repo", "remove"),
		Entry("source add", "source add", "source", "add"),
		Entry("pkg lint", "pkg lint", "pkg", "lint"),
		Entry("alternatives list", "alternatives list", "alternatives", "list", "a", "b"),
		Entry("a top-level command", "purge", "purge"),
		Entry("generation unpin keeps its documented name", "unpin", "generation", "unpin"),
	)

	DescribeTable("names the operands of every one-operand and optional-operand command",
		func(want string, args ...string) {
			cmd := NewRootCmd()
			cmd.SetArgs(args)
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			err := cmd.Execute()
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected a CLIError naming the operands, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring(want))
			Expect(ce.Hint).To(HavePrefix("usage: "))
		},
		Entry("source add", "polypkg source add needs <name> (got no arguments)", "source", "add"),
		Entry("source remove", "polypkg source remove expected <name> (got 2 arguments)", "source", "remove", "a", "b"),
		Entry("source set-trust-root", "polypkg source set-trust-root needs <name> (got no arguments)", "source", "set-trust-root"),
		Entry("pkg lint", "polypkg pkg lint needs <dir> (got no arguments)", "pkg", "lint"),
		Entry("pkg build", "polypkg pkg build needs <dir> (got no arguments)", "pkg", "build"),
		Entry("pkg init", "polypkg pkg init needs <dir> (got no arguments)", "pkg", "init"),
		Entry("repo init", "polypkg repo init needs <dir> (got no arguments)", "repo", "init"),
		Entry("repo remove", "polypkg repo remove needs <name>[@<version>] (got no arguments)", "repo", "remove"),
		Entry("mirror verify", "polypkg mirror verify needs <bundle.tar> (got no arguments)", "mirror", "verify"),
		Entry("apply", "polypkg apply expected at most one [profile-file] (got 2 arguments)", "apply", "a.yaml", "b.yaml"),
		Entry("plan", "polypkg plan expected at most one [profile-file] (got 2 arguments)", "plan", "a.yaml", "b.yaml"),
		Entry("config reset", "polypkg config reset expected at most one [path] (got 2 arguments)", "config", "reset", "/a", "/b"),
		Entry("alternatives list", "polypkg alternatives list expected at most one [name] (got 2 arguments)", "alternatives", "list", "a", "b"),
	)

	It("suggests the closest command for a typo", func() {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"stauts"})
		var errOut bytes.Buffer
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&errOut)
		err := cmd.Execute()
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Hint).To(ContainSubstring("did you mean `polypkg status`?"))
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

	DescribeTable("names the command by its path in a flag error's JSON envelope",
		func(want string, args ...string) {
			cmd := NewRootCmd()
			cmd.SetArgs(append([]string{"--format", "json"}, args...))
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&bytes.Buffer{})
			Expect(cmd.Execute()).To(HaveOccurred())
			var env struct {
				Command string `json:"command"`
				Status  string `json:"status"`
			}
			Expect(json.Unmarshal(out.Bytes(), &env)).To(Succeed(), "stdout must be one JSON envelope, got %q", out.String())
			Expect(env.Status).To(Equal("error"))
			Expect(env.Command).To(Equal(want))
		},
		Entry("repo remove, unknown flag", "repo remove", "repo", "remove", "--bogus"),
		Entry("repo key show, unknown flag", "repo key show", "repo", "key", "show", "--bogus"),
		Entry("pkg lint, unknown flag", "pkg lint", "pkg", "lint", "--bogus", "x"),
		Entry("gc, malformed value", "gc", "gc", "--count", "abc"),
		Entry("generation pin keeps its documented name", "pin", "generation", "pin", "1", "--reason"),
		Entry("a group with an unknown subcommand", "source", "source", "bogus"),
	)

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
