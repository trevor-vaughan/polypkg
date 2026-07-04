package action

import (
	"fmt"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// Unmanaged records ownership of a path without providing content — the RPM
// %ghost analog, for logs, runtime sockets, PID files, and dynamically
// generated config. It creates nothing on disk and is never drift-checked; the
// ownership entry exists for lifecycle tracking and future conflict detection.
func Unmanaged(inv Invocation, scope Scope) (Result, error) {
	path, ok := inv.Params["path"].(string)
	if !ok || path == "" {
		return Result{}, fmt.Errorf("unmanaged: missing required param 'path'")
	}
	if !scope.Allows(path) {
		return Result{}, fmt.Errorf("unmanaged: %q is outside the package scope", path)
	}
	return Result{
		Action:      inv.Action,
		Path:        path,
		Outcome:     "ok",
		Expected:    schema.Expected{FileType: "ghost"},
		DriftPolicy: "unmanaged",
	}, nil
}
