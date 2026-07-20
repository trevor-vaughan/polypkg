package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/trevor-vaughan/polypkg/internal/cli/style"
)

// RenderError writes the final user-facing error to w (normally stderr):
// a styled "error:" line, plus a "hint:" line when the error carries one.
// Quiet StatusErrors (plan's changes-pending) render nothing.
func RenderError(w io.Writer, err error) {
	if err == nil {
		return
	}
	var se *StatusError
	if errors.As(err, &se) && se.Quiet {
		return
	}
	st := style.ForWriter(w)
	msg, hint := err.Error(), ""
	var ce *CLIError
	if errors.As(err, &ce) {
		msg, hint = ce.Msg, ce.Hint
	}
	fmt.Fprintf(w, "%s %s\n", st.Error.Render("error:"), msg)
	if hint != "" {
		fmt.Fprintln(w, st.Hint.Render("hint: "+hint))
	}
}

// ExitCode maps an error to the process exit code: 0 for nil, a
// StatusError's carried code, otherwise 1.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return 1
}
