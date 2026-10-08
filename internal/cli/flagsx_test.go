package cli

import (
	"bytes"
	"encoding/json"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// declaredRequiredFlags is every flag of cmd declared required, whether
// through requireFlags or through cobra's MarkFlagRequired (whose error
// bypasses the JSON envelope, so the spec below fails for any that use it).
func declaredRequiredFlags(cmd *cobra.Command) []string {
	var names []string
	if list := cmd.Annotations[requiredFlagsAnnotation]; list != "" {
		names = strings.Split(list, ",")
	}
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if _, ok := f.Annotations[cobra.BashCompOneRequiredFlag]; ok {
			names = append(names, f.Name)
		}
	})
	return names
}

// operandPlaceholders returns one dummy value per mandatory <operand> in
// cmd's Use line, so its Args validator passes and the flag check is what
// fails.
func operandPlaceholders(cmd *cobra.Command) []string {
	var args []string
	for _, field := range strings.Fields(cmd.Use)[1:] {
		if strings.HasPrefix(field, "<") {
			args = append(args, "placeholder")
		}
	}
	return args
}

var _ = Describe("required flags", func() {
	It("report every missing required flag in a cli-result envelope under --format json", func() {
		sandboxUserEnv(GinkgoTB())
		checked := 0
		var walk func(cmd *cobra.Command)
		walk = func(cmd *cobra.Command) {
			for _, sub := range cmd.Commands() {
				walk(sub)
			}
			required := declaredRequiredFlags(cmd)
			if len(required) == 0 {
				return
			}
			checked++
			path := strings.Fields(cmd.CommandPath())[1:]
			root := NewRootCmd()
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&bytes.Buffer{})
			root.SetArgs(append(append([]string{"-f", "json"}, path...), operandPlaceholders(cmd)...))
			Expect(root.Execute()).To(HaveOccurred(), cmd.CommandPath())

			var env struct {
				Schema  string `json:"schema"`
				Command string `json:"command"`
				Status  string `json:"status"`
				Error   string `json:"error"`
				Hint    string `json:"hint"`
			}
			Expect(json.Unmarshal(out.Bytes(), &env)).To(Succeed(),
				"%s: stdout must be one JSON envelope, got %q", cmd.CommandPath(), out.String())
			Expect(env.Schema).To(Equal("polypkg.cli-result/v2"), cmd.CommandPath())
			Expect(env.Command).To(Equal(strings.Join(path, " ")), cmd.CommandPath())
			Expect(env.Status).To(Equal("error"), cmd.CommandPath())
			Expect(env.Error).To(HavePrefix(cmd.CommandPath()+" needs "), cmd.CommandPath())
			for _, name := range required {
				Expect(env.Error).To(ContainSubstring("--"+name), cmd.CommandPath())
				Expect(env.Hint).To(ContainSubstring("--"+name), cmd.CommandPath())
			}
			Expect(env.Hint).To(HavePrefix("usage: "), cmd.CommandPath())
		}
		walk(NewRootCmd())
		Expect(checked).To(BeNumerically(">=", 4), "the walk must reach the commands with required flags")
	})

	It("names only the flags still missing", func() {
		sandboxUserEnv(GinkgoTB())
		_, stderr, code := runRoot("mirror", "pull", "--key", "k")

		Expect(code).NotTo(BeZero())
		Expect(stderr).To(ContainSubstring("polypkg mirror pull needs --repo-source and --output-dir"))
	})
})
