package repo

// PublishError is a publisher-side, user-causable error carrying an actionable
// hint. The CLI layer maps it onto the shared CLIError contract.
type PublishError struct {
	Msg  string
	Hint string
	Err  error
}

func (e *PublishError) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func (e *PublishError) Unwrap() error { return e.Err }

// HintText exposes the hint for the CLI mapping layer.
func (e *PublishError) HintText() string { return e.Hint }
