package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// needsArgs replaces cobra.ExactArgs/MinimumNArgs with messages naming the
// missing operands ("polypkg generation pin needs <generation-id>") instead
// of arg counts. operands is the placeholder text from the command's Use
// line; maximum < 0 means unbounded.
func needsArgs(minimum, maximum int, operands string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) >= minimum && (maximum < 0 || len(args) <= maximum) {
			return nil
		}
		verb := "needs"
		if len(args) > 0 {
			verb = "expected"
		}
		err := &CLIError{
			Msg:  fmt.Sprintf("%s %s %s (got %s)", cmd.CommandPath(), verb, operands, countArgs(len(args))),
			Hint: "usage: " + cmd.UseLine(),
		}
		// Args validators run before RunE, so RunE's WrapError never sees
		// this error; emit the JSON envelope here. Flags are already parsed.
		format, ferr := resolveFormat(cmd)
		if ferr != nil {
			format = FormatText
		}
		return WrapError(cmd, format, cmd.Name(), err)
	}
}

// countArgs renders a grammatical argument count: "no arguments",
// "1 argument", "3 arguments".
func countArgs(n int) string {
	switch n {
	case 0:
		return "no arguments"
	case 1:
		return "1 argument"
	default:
		return fmt.Sprintf("%d arguments", n)
	}
}
