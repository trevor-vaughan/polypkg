package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// requireSubcommand builds the RunE for a command group that has no behaviour
// of its own. Without it cobra treats a non-runnable command as a help request:
// `polypkg repo` prints the group's help to stdout and exits 0, so a script
// silently succeeds having done nothing and a `--format json` consumer receives
// English prose. This RunE turns both a missing and an unrecognised subcommand
// into a CLIError instead — message and hint on stderr, a cli-result/v2 error
// envelope under --format json, and a non-zero exit — matching what an unknown
// top-level command already does.
//
// unknownHint overrides the default recovery line for the unrecognised-
// subcommand case only; pass "" to point at the group's own --help for both.
// Groups installing this must also set Args to cobra.ArbitraryArgs so the
// unrecognised name reaches RunE rather than being rejected by an arg count.
func requireSubcommand(unknownHint string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		ce := &CLIError{
			Msg:  fmt.Sprintf("%s requires a subcommand", cmd.CommandPath()),
			Hint: fmt.Sprintf("run `%s --help` to list subcommands", cmd.CommandPath()),
		}
		if len(args) > 0 {
			ce.Msg = fmt.Sprintf("unknown %s subcommand %q", cmd.Name(), args[0])
			if unknownHint != "" {
				ce.Hint = unknownHint
			}
		}
		format, ferr := resolveFormat(cmd)
		if ferr != nil {
			format = FormatText
		}
		return WrapError(cmd, format, cmd.Name(), ce)
	}
}
