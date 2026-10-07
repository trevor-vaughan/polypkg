package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// resultCommandAnnotation, set in a command's Annotations, overrides the
// command name an argument or flag error's JSON envelope reports, for a command whose
// results have always used a name other than its path.
const resultCommandAnnotation = "polypkg.result-command"

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
		return wrapInvocationError(cmd, err)
	}
}

// resultCommand is the command value an error envelope reports for cmd: the
// name its own results use, which is its path without the root
// ("repo remove") unless it declares another name. The root itself, which
// rejects an unknown command, reports its own name: the envelope schema
// requires a non-empty command.
func resultCommand(cmd *cobra.Command) string {
	if name, ok := cmd.Annotations[resultCommandAnnotation]; ok {
		return name
	}
	if !cmd.HasParent() {
		return cmd.Name()
	}
	return strings.TrimPrefix(cmd.CommandPath(), cmd.Root().Name()+" ")
}

// wrapInvocationError is WrapError for an error about how cmd was invoked
// (arguments, flags, subcommand), raised where no RunE has resolved the
// format. An unparseable --format falls back to text: the invocation error
// is the one to report, not the format's.
func wrapInvocationError(cmd *cobra.Command, err error) error {
	format, ferr := resolveFormat(cmd)
	if ferr != nil {
		format = FormatText
	}
	return WrapError(cmd, format, resultCommand(cmd), err)
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
