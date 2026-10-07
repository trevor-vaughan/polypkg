package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// Format selects the output format for a CLI command.
type Format int

const (
	// FormatText is the default human-readable output.
	FormatText Format = iota
	// FormatJSON emits a stable structured schema (cli-result/v2 for
	// action commands; plan/v1 and status/v1 for plan and status).
	FormatJSON
)

// cliResultSchema is the schema string stamped into every cli-result envelope.
const cliResultSchema = "polypkg.cli-result/v2"

// ParseFormat resolves a --format flag value. Empty defaults to FormatText.
func ParseFormat(s string) (Format, error) {
	switch s {
	case "", "text":
		return FormatText, nil
	case "json":
		return FormatJSON, nil
	default:
		return FormatText, fmt.Errorf("invalid --format %q (expected text or json)", s)
	}
}

// resolveFormat reads the persistent --format flag from cmd and parses it.
// Returns FormatText with no error if the flag is absent (e.g. in unit
// tests that don't set up the root flag).
func resolveFormat(cmd *cobra.Command) (Format, error) {
	flag := cmd.Flag("format")
	if flag == nil {
		return FormatText, nil
	}
	return ParseFormat(flag.Value.String())
}

// EmitResult writes the command's success output to cmd.OutOrStdout().
// In text mode it calls textRenderer with a *bytes.Buffer the caller can
// freely write into; the buffer's contents are then flushed to stdout.
// In json mode it marshals a polypkg.cli-result/v2 envelope and ignores
// textRenderer.
//
// textRenderer may be nil — only required when callers want a bespoke
// text rendering. Under FormatJSON, textRenderer is ignored.
func EmitResult(
	cmd *cobra.Command,
	f Format,
	command string,
	data map[string]any,
	textRenderer func(w *bytes.Buffer, data map[string]any),
) {
	if f == FormatJSON {
		env := schema.CLIResult{
			Schema:  cliResultSchema,
			Command: command,
			Status:  "ok",
			Data:    data,
		}
		out, _ := json.Marshal(&env)
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return
	}
	if textRenderer == nil {
		return
	}
	var buf bytes.Buffer
	textRenderer(&buf, data)
	fmt.Fprint(cmd.OutOrStdout(), buf.String())
}

// WrapError emits an error envelope under FormatJSON or no-ops under
// FormatText (cobra's default error printing kicks in). Returns the
// input error so the caller's RunE can `return WrapError(...)` and let
// cobra propagate the non-zero exit.
func WrapError(cmd *cobra.Command, f Format, command string, err error) error {
	if err == nil {
		return nil
	}
	err = withRecoveryHint(err)
	if f == FormatJSON {
		env := schema.CLIResult{
			Schema:  cliResultSchema,
			Command: command,
			Status:  "error",
		}
		// A CLIError's Msg is the complete user-facing message by contract;
		// wrapper context (e.g. "open profile: …") is log detail, deliberately
		// stripped here exactly as RenderError strips it in text mode.
		var ce *CLIError
		if errors.As(err, &ce) {
			env.Error = ce.Msg
			env.Hint = ce.Hint
		} else {
			env.Error = err.Error()
		}
		out, _ := json.Marshal(&env)
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	}
	return err
}

// withRecoveryHint upgrades known typed errors from lower layers into
// CLIErrors carrying an actionable hint. The full wrapped chain is kept as
// the message (unlike hand-built CLIErrors, whose Msg is standalone by
// contract) because the chain carries the source context ("source \"x\": ...").
func withRecoveryHint(err error) error {
	var ce *CLIError
	if errors.As(err, &ce) {
		return err // already carries its own message+hint
	}
	var mm *trust.SourceNameMismatchError
	if errors.As(err, &mm) {
		// Err is set so that errors.As(*trust.SourceNameMismatchError) still
		// resolves through the CLIError wrapper. CLIError.Error() returns only
		// Msg, so Err does not duplicate the user-facing text.
		return &CLIError{
			Msg: err.Error(),
			Hint: fmt.Sprintf("this repository publishes source %q; add it with `polypkg source add %s --url <repo-url> --trust-root <pub>` and remove the misnamed source, or re-run `polypkg init --source-name %s`",
				mm.Doc, mm.Doc, mm.Doc),
			Err: err,
		}
	}
	var ne *schema.NewerSchemaError
	if errors.As(err, &ne) {
		return newerStateError(err, ne)
	}
	return err
}

// newerStateError is the user-facing error for err, whose chain holds ne: a
// document a newer polypkg wrote. A named file makes ne's own sentence
// complete; without one (a fetched document), the whole chain is kept so its
// context ("source \"x\": …") says which document it was, and the hint names
// the repository rather than local state.
func newerStateError(err error, ne *schema.NewerSchemaError) *CLIError {
	msg, subject := ne.Error(), "running polypkg against this state"
	if ne.Path == "" {
		msg, subject = err.Error(), "using this repository"
	}
	return &CLIError{
		Msg:  msg,
		Hint: fmt.Sprintf("you are running polypkg %s; install a newer release (see the README's Install section) before %s", Version, subject),
		Err:  err,
	}
}
