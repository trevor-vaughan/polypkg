package starlarkeval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// ChildCommand is the hidden subcommand name the parent re-execs and the child
// dispatches on.
const ChildCommand = "__eval-starlark"

type evalRequest struct {
	Source         string `json:"source"`
	Inputs         Inputs `json:"inputs"`
	MaxSteps       uint64 `json:"max_steps"`
	MaxMemoryBytes uint64 `json:"max_memory_bytes"`
	MaxOutputBytes int    `json:"max_output_bytes"`
}

type evalResponse struct {
	Result string `json:"result"`
	Err    string `json:"err"`
}

// RunChild is the entrypoint for the re-exec'd evaluation subprocess. It reads a
// request from stdin, evaluates in-process under GOMEMLIMIT, writes a response
// to stdout, and exits. It never writes anything but the JSON response to stdout
// (Starlark print goes to stderr).
func RunChild() {
	var req evalRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		writeResponse(evalResponse{Err: "decode request: " + err.Error()})
		os.Exit(0)
	}
	if req.MaxMemoryBytes > 0 && req.MaxMemoryBytes <= math.MaxInt64 {
		//nolint:gosec // G115: bounded above by math.MaxInt64 on the line above.
		debug.SetMemoryLimit(int64(req.MaxMemoryBytes)) // soft GC target
	}
	lim := Limits{MaxSteps: req.MaxSteps, MaxOutputBytes: req.MaxOutputBytes, MaxMemoryBytes: req.MaxMemoryBytes}
	// The child relies on the parent's SIGKILL (process-group) for wall-clock and
	// memory enforcement, so it runs with a background context; the step cap and
	// output cap are enforced here in-process.
	res, err := Run(context.Background(), req.Source, req.Inputs, lim)
	resp := evalResponse{Result: res}
	if err != nil {
		resp.Err = err.Error()
	}
	writeResponse(resp)
	os.Exit(0)
}

func writeResponse(resp evalResponse) {
	b, _ := json.Marshal(resp)
	_, _ = os.Stdout.Write(b)
}

// cappedBuffer collects up to cap bytes and silently discards the rest, so a
// chatty child cannot grow the parent's stderr capture without bound. It always
// reports a full write so the child's writes never error.
type cappedBuffer struct {
	buf bytes.Buffer
	cap int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if remaining := c.cap - c.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			c.buf.Write(p[:remaining])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return c.buf.String() }

// Evaluate runs source in a disposable child process (fault isolation) with the
// given limits: step + output caps and GOMEMLIMIT in the child, and
// parent-enforced wall-clock timeout plus (Linux) RSS ceiling.
func Evaluate(ctx context.Context, source string, in Inputs, lim Limits) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate self for eval child: %w", err)
	}
	req := evalRequest{
		Source: source, Inputs: in,
		MaxSteps: lim.MaxSteps, MaxMemoryBytes: lim.MaxMemoryBytes, MaxOutputBytes: lim.MaxOutputBytes,
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("encode eval request: %w", err)
	}

	//nolint:gosec // G204: re-exec of our own binary (os.Executable); ChildCommand
	// is a package constant and there is no external input in the command line.
	cmd := exec.Command(self, ChildCommand)
	cmd.Stdin = bytes.NewReader(reqBytes)
	var stdout bytes.Buffer
	stderr := &cappedBuffer{cap: 64 << 10} // bound child stderr (print spam)
	cmd.Stdout = &stdout
	cmd.Stderr = stderr
	setProcAttr(cmd)

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start eval child: %w", err)
	}

	killed := make(chan string, 1)
	done := make(chan struct{})

	// killOnce kills the child's process group with a reason, but never after
	// Wait has reaped it — so a late timer/ctx/RSS fire cannot signal a recycled
	// PID, and a snippet that finished cleanly is never reported as killed.
	var mu sync.Mutex
	reaped := false
	killOnce := func(reason string) {
		mu.Lock()
		defer mu.Unlock()
		if reaped {
			return
		}
		select {
		case killed <- reason:
		default:
		}
		killChild(cmd)
	}

	if lim.Timeout > 0 {
		timer := time.AfterFunc(lim.Timeout, func() { killOnce("timed out") })
		defer timer.Stop()
	}
	go func() {
		select {
		case <-ctx.Done():
			killOnce("cancelled")
		case <-done:
		}
	}()
	if lim.MaxMemoryBytes > 0 {
		go monitorRSS(cmd.Process.Pid, lim.MaxMemoryBytes, done, func() { killOnce("memory limit exceeded") })
	}

	waitErr := cmd.Wait()
	mu.Lock()
	reaped = true
	mu.Unlock()
	close(done)

	// waitErr != nil means the child died abnormally (a limiter's SIGKILL, an
	// OOM, or a panic). Only then is a kill reason authoritative; a clean exit
	// (waitErr == nil) always yields the computed result, even if a limiter
	// raced the child's completion.
	if waitErr != nil {
		select {
		case reason := <-killed:
			return "", fmt.Errorf("starlark evaluation %s", reason)
		default:
		}
		return "", fmt.Errorf("evaluation process failed: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	var resp evalResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return "", fmt.Errorf("decode eval response: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	if resp.Err != "" {
		return "", errors.New(resp.Err)
	}
	return resp.Result, nil
}

func monitorRSS(pid int, maxBytes uint64, done <-chan struct{}, onBreach func()) {
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			rss, err := sampleRSS(pid)
			if err != nil {
				return // unsupported OS, or process already gone
			}
			if rss > maxBytes {
				onBreach()
				return
			}
		}
	}
}

// Evaluator evaluates snippets through a pluggable backend and caches results
// within its lifetime (one apply), keyed by source + package identity.
type Evaluator struct {
	backend func(context.Context, string, Inputs, Limits) (string, error)
	lim     Limits
	mu      sync.Mutex
	cache   map[string]string
}

// NewEvaluator returns an Evaluator that isolates each evaluation in a subprocess.
func NewEvaluator(lim Limits) *Evaluator {
	return &Evaluator{backend: Evaluate, lim: lim, cache: map[string]string{}}
}

// NewInProcessEvaluator returns an Evaluator that evaluates in-process (no
// subprocess). Intended for tests and callers that do not need isolation.
func NewInProcessEvaluator(lim Limits) *Evaluator {
	return &Evaluator{backend: Run, lim: lim, cache: map[string]string{}}
}

// Eval computes source under in, returning a cached result when the same source
// was already evaluated for the same package.
func (e *Evaluator) Eval(ctx context.Context, source string, in Inputs) (string, error) {
	// Length-prefix each component so no value can forge a delimiter and collide
	// with a different (name, version, source) triple.
	key := fmt.Sprintf("%d:%s%d:%s%s", len(in.Package.Name), in.Package.Name, len(in.Package.Version), in.Package.Version, source)
	e.mu.Lock()
	v, ok := e.cache[key]
	e.mu.Unlock()
	if ok {
		return v, nil
	}
	res, err := e.backend(ctx, source, in, e.lim)
	if err != nil {
		return "", err
	}
	e.mu.Lock()
	e.cache[key] = res
	e.mu.Unlock()
	return res, nil
}
