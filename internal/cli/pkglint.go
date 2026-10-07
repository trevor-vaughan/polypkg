package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

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
		Args: needsArgs(1, 1, "<dir>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			err := runPkgLint(cmd, format, args[0], sarif, outPath)
			if errors.Is(err, errLintFailed) && sarif && outPath == "" {
				// The SARIF document on stdout is the result; an envelope
				// after it would make stdout two JSON documents.
				return err
			}
			return WrapError(cmd, format, "pkg lint", err)
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

func runPkgLint(cmd *cobra.Command, format Format, dir string, sarif bool, outPath string) error {
	if outPath != "" && !sarif {
		return &CLIError{
			Msg:  "-o/--output needs --sarif",
			Hint: "add --sarif to write a SARIF report to that file; the human report is never written to a file: it goes to stdout, or to stderr under --format json",
		}
	}
	res, err := pkglint.Lint(dir)
	if err != nil {
		return packageSourceError(dir, err)
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
		pkglint.WriteHuman(humanReportWriter(cmd, format), res)
	}
	if res.HasErrors() {
		return errLintFailed
	}
	return nil
}

// humanReportWriter is where a lint report for a person goes: stdout in text
// mode, stderr under --format json so stdout carries only the JSON envelope.
func humanReportWriter(cmd *cobra.Command, format Format) io.Writer {
	if format == FormatJSON {
		return cmd.ErrOrStderr()
	}
	return cmd.OutOrStdout()
}

// packageSourceError is the user-facing error for a package directory whose
// polypkg.yaml cannot be read (pkglint.Lint's only error).
func packageSourceError(dir string, err error) *CLIError {
	msg := fsFailureMsg("cannot read "+filepath.Join(dir, "polypkg.yaml"), err)
	if errors.Is(err, fs.ErrNotExist) {
		msg = dir + " has no polypkg.yaml"
		if _, serr := os.Stat(dir); errors.Is(serr, fs.ErrNotExist) {
			msg = "package directory " + dir + " does not exist"
		}
	}
	return &CLIError{
		Msg:  msg,
		Hint: "a package directory must contain a polypkg.yaml (schema polypkg.package/v1) and a content/ tree; `polypkg pkg init <dir>` scaffolds one",
		Err:  err,
	}
}
