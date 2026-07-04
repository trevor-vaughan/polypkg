package cli

// CLIError is an error written for the user: Msg says what went wrong in
// user terms, Hint (optional) names the next command to run, Err carries
// the wrapped cause for %w chains and logs. Never put Go internals
// (syscall text, type names) in Msg.
//
//nolint:revive // cli.CLIError stutters, but in-package the name disambiguates from StatusError; nothing outside internal/cli references the type.
type CLIError struct {
	Msg  string
	Hint string
	Err  error
}

func (e *CLIError) Error() string { return e.Msg }
func (e *CLIError) Unwrap() error { return e.Err }

// StatusError selects the process exit code. Quiet suppresses stderr
// rendering — used by `plan`, whose changes-pending result is already the
// stdout body.
type StatusError struct {
	Code  int
	Quiet bool
	Msg   string
}

func (e *StatusError) Error() string { return e.Msg }

// ExitCode returns the process exit code main should use for this error.
func (e *StatusError) ExitCode() int { return e.Code }
