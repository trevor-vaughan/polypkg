package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// installFlagErrorFunc sets a flag-parse error handler on root that
// translates pflag typed errors into CLIErrors, then emits a JSON
// envelope when --format json was already parsed (flags are parsed
// left-to-right; if the format flag itself failed, we fall back to text).
// Because cobra's FlagErrorFunc() walks to c.parent when c has none of
// its own, setting it once on root covers all subcommands.
func installFlagErrorFunc(root *cobra.Command) {
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		ce := translateFlagError(cmd, err)
		format, ferr := resolveFormat(cmd)
		if ferr != nil {
			format = FormatText
		}
		return WrapError(cmd, format, cmd.Name(), ce)
	})
}

// translateFlagError converts a pflag parse error into a *CLIError with
// user-readable Msg/Hint and the original pflag error as Err.
func translateFlagError(cmd *cobra.Command, err error) *CLIError {
	var notExist *pflag.NotExistError
	if errors.As(err, &notExist) {
		name := notExist.GetSpecifiedName()
		msg := "unknown flag --" + name
		hint := suggestFlag(cmd, name)
		if hint == "" {
			hint = "usage: " + cmd.UseLine()
		} else {
			hint = fmt.Sprintf("did you mean --%s? (usage: %s)", hint, cmd.UseLine())
		}
		return &CLIError{Msg: msg, Hint: hint, Err: err}
	}

	var valReq *pflag.ValueRequiredError
	if errors.As(err, &valReq) {
		name := valReq.GetSpecifiedName()
		return &CLIError{
			Msg:  fmt.Sprintf("--%s needs a value", name),
			Hint: "usage: " + cmd.UseLine(),
			Err:  err,
		}
	}

	var invVal *pflag.InvalidValueError
	if errors.As(err, &invVal) {
		flag := invVal.GetFlag()
		value := invVal.GetValue()
		typeName := friendlyTypeName(flag.Value.Type())
		msg := fmt.Sprintf("invalid value %q for --%s", value, flag.Name)
		if typeName != "" {
			msg = fmt.Sprintf("invalid value %q for --%s (expected %s)", value, flag.Name, typeName)
		}
		return &CLIError{Msg: msg, Hint: "usage: " + cmd.UseLine(), Err: err}
	}

	// Unknown pflag error type: wrap as-is but strip internals.
	return &CLIError{Msg: err.Error(), Err: err}
}

// suggestFlag returns the name (without dashes) of a defined flag on cmd
// that is a plausible match for the misspelled input: same prefix of
// length >= 2 or edit distance exactly 1. Returns "" when no match is
// found. Keeps the logic minimal — no external deps.
func suggestFlag(cmd *cobra.Command, input string) string {
	var best string
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if best != "" {
			return // already found one
		}
		candidate := f.Name
		if len(input) >= 2 && strings.HasPrefix(candidate, input[:2]) {
			best = candidate
			return
		}
		if editDistance1(input, candidate) {
			best = candidate
		}
	})
	return best
}

// editDistance1 reports whether a and b differ by exactly one edit
// (substitution, insertion, or deletion). This is a fast O(n) check
// rather than full Levenshtein — sufficient for short flag names.
func editDistance1(a, b string) bool {
	la, lb := len(a), len(b)
	if la == lb {
		// Substitution: exactly one differing byte.
		diff := 0
		for i := range la {
			if a[i] != b[i] {
				diff++
				if diff > 1 {
					return false
				}
			}
		}
		return diff == 1
	}
	// Insertion or deletion: lengths differ by exactly 1.
	if la > lb+1 || lb > la+1 {
		return false
	}
	// Ensure a is the shorter string.
	if la > lb {
		a, b = b, a
		la, lb = lb, la
	}
	// One insertion in a = one deletion in b.
	i, j, skipped := 0, 0, false
	for i < la && j < lb {
		if a[i] == b[j] {
			i++
			j++
		} else {
			if skipped {
				return false
			}
			skipped = true
			j++ // skip one char in the longer string
		}
	}
	return true
}

// friendlyTypeName converts a pflag Value.Type() string to a human phrase.
// Returns "" for types we have no friendly name for.
func friendlyTypeName(t string) string {
	switch t {
	case "int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64":
		return "a number"
	case "float32", "float64":
		return "a number"
	case "duration":
		return "a duration"
	case "bool":
		return "true or false"
	default:
		return ""
	}
}
