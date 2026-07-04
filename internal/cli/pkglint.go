package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/pkglint"
)

// errLintFailed signals that lint produced error-severity findings. The message
// is terse because the findings themselves were already rendered to the user;
// the root command sets SilenceUsage/SilenceErrors, so returning it yields a
// non-zero exit without re-printing usage or a redundant error line.
var errLintFailed = &CLIError{Msg: "lint found error-severity issues"}

func newPkgLintCmd() *cobra.Command {
	var sarif bool
	var outPath string
	cmd := &cobra.Command{
		Use:   "lint <dir>",
		Short: "Validate a package source (human or SARIF)",
		Long: `Validate <dir>/polypkg.yaml and its content tree against structure, action,
parameter, and identity rules. Exits non-zero if any error-severity finding
fires. --sarif emits canonical SARIF 2.1.0 — the same predicate the publisher
signs; with -o it writes to a file instead of stdout.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPkgLint(cmd, args[0], sarif, outPath)
		},
	}
	// A boolean --sarif avoids colliding with the root's persistent -f/--format
	// (text/json), which governs the cli-result envelope. A local --format flag
	// would orphan the inherited -f shorthand and crash any invocation that uses
	// it. -o only takes effect in SARIF mode.
	cmd.Flags().BoolVar(&sarif, "sarif", false, "Emit canonical SARIF 2.1.0 instead of human output")
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "Write SARIF to this file instead of stdout (SARIF mode only)")
	return cmd
}

func runPkgLint(cmd *cobra.Command, dir string, sarif bool, outPath string) error {
	res, err := pkglint.Lint(dir)
	if err != nil {
		return &CLIError{Msg: fmt.Sprintf("cannot lint %q", dir), Err: err}
	}
	if sarif {
		out, serr := pkglint.SARIF(res)
		if serr != nil {
			return &CLIError{Msg: "render SARIF", Err: serr}
		}
		if outPath != "" {
			if werr := os.WriteFile(outPath, out, 0o644); werr != nil { //nolint:gosec // SARIF report is public output; author-chosen path
				return &CLIError{Msg: fmt.Sprintf("cannot write SARIF to %q", outPath), Err: werr}
			}
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
		}
	} else {
		pkglint.WriteHuman(cmd.OutOrStdout(), res)
	}
	if res.HasErrors() {
		return errLintFailed
	}
	return nil
}
