// Package starlarkeval evaluates a package's !starlark snippets in a sandboxed,
// subprocess-isolated environment to compute action parameter values.
package starlarkeval

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

// Inputs are the values exposed to a snippet as Starlark globals.
type Inputs struct {
	Package struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"package"`
	Host struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
	} `json:"host"`
}

// Limits bound a single evaluation. A zero MaxSteps or MaxOutputBytes means
// "unlimited"; production callers always populate them via
// schema.ResolveStarlarkLimits, which fills defaults.
type Limits struct {
	// MaxSteps caps Starlark execution steps; 0 means unlimited. Enforced by Run.
	MaxSteps uint64
	// Timeout is the wall-clock budget; enforced by the subprocess wrapper
	// (Evaluate), not by Run.
	Timeout time.Duration
	// MaxMemoryBytes caps memory; enforced by the subprocess wrapper (GOMEMLIMIT
	// in the child plus the parent RSS monitor), not by Run.
	MaxMemoryBytes uint64
	// MaxOutputBytes caps the returned string's byte length; 0 means unlimited.
	// Enforced by Run.
	MaxOutputBytes int
}

const snippetFile = "snippet.star"

var lineRe = regexp.MustCompile(`(snippet\.star:)(\d+)(:)`)

// remapLine rewrites "snippet.star:N:" line numbers to be author-relative (the
// generated `def _polypkg_main():` occupies line 1, shifting the body by +1).
// N==1 would be the wrapper line itself, which authors never write, so the
// guarded decrement never needs to emit a confusing line 0 in practice.
func remapLine(msg string) string {
	return lineRe.ReplaceAllStringFunc(msg, func(m string) string {
		sub := lineRe.FindStringSubmatch(m)
		n, _ := strconv.Atoi(sub[2])
		if n > 0 {
			n--
		}
		return sub[1] + strconv.Itoa(n) + sub[3]
	})
}

func indentSnippet(src string) string {
	lines := strings.Split(src, "\n")
	for i, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		lines[i] = "\t" + ln
	}
	return strings.Join(lines, "\n")
}

// Run evaluates source in-process and returns its string result. It enforces the
// step and output caps and honours ctx cancellation; memory and wall-clock are
// enforced by the subprocess wrapper (see Evaluate).
func Run(ctx context.Context, source string, in Inputs, lim Limits) (string, error) {
	// Reject an already-cancelled context before touching the interpreter.
	if err := ctx.Err(); err != nil {
		return "", err
	}

	wrapped := "def _polypkg_main():\n" + indentSnippet(source) + "\n"

	thread := &starlark.Thread{
		Name:  "polypkg-starlark",
		Print: func(_ *starlark.Thread, msg string) { fmt.Fprintln(os.Stderr, "[starlark]", msg) },
	}
	if lim.MaxSteps > 0 {
		thread.SetMaxExecutionSteps(lim.MaxSteps)
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			thread.Cancel("context cancelled")
		case <-done:
		}
	}()

	predeclared := starlark.StringDict{
		"package": starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
			"name":    starlark.String(in.Package.Name),
			"version": starlark.String(in.Package.Version),
		}),
		"host": starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
			"os":   starlark.String(in.Host.OS),
			"arch": starlark.String(in.Host.Arch),
		}),
	}

	globals, err := starlark.ExecFileOptions(&syntax.FileOptions{}, thread, snippetFile, wrapped, predeclared)
	if err != nil {
		return "", fmt.Errorf("%s", remapLine(err.Error()))
	}
	fn, ok := globals["_polypkg_main"].(starlark.Callable)
	if !ok {
		return "", fmt.Errorf("internal: snippet wrapper produced no function")
	}
	res, err := starlark.Call(thread, fn, nil, nil)
	if err != nil {
		return "", fmt.Errorf("%s", remapLine(err.Error()))
	}
	sv, ok := res.(starlark.String)
	if !ok {
		return "", fmt.Errorf("computed value must be a string, got %s", res.Type())
	}
	s := string(sv)
	if lim.MaxOutputBytes > 0 && len(s) > lim.MaxOutputBytes {
		return "", fmt.Errorf("computed value is %d bytes, exceeds output limit %d", len(s), lim.MaxOutputBytes)
	}
	return s, nil
}
