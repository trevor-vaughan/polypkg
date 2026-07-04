package cli

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/trevor-vaughan/polypkg/internal/lock"
)

// isLockConflictError reports whether err (or any error in its chain)
// contains the fixed sentinel string produced by lock.acquireFlock when
// a non-blocking acquire fails. This is used to translate runner-level
// lock errors at the CLI boundary without adding a typed sentinel to the
// lock package.
func isLockConflictError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "lock is held by another process")
}

// lockError translates a lock.Acquire failure into a user-facing *CLIError.
// When the lock file is readable, holds valid metadata, and the recorded PID
// is still alive, the message names the holder's command and PID. When the
// recorded PID is dead or unreadable (e.g. the holder crashed and an
// unrelated process grabbed the flock), the message is generic and the hint
// names the lock file path so the user can investigate.
// Call this only when lock.Acquire returns a non-nil error.
//
// lockPath must be the same path passed to lock.Acquire so ReadMetadata can
// find the file.
func lockError(lockPath string, err error) *CLIError {
	const aliveHint = "wait for it to finish; a crashed process releases the lock automatically"

	meta, merr := lock.ReadMetadata(lockPath)
	if merr == nil && meta != nil && pidAlive(meta.PID) {
		msg := buildHolderMsg(meta)
		return &CLIError{Msg: msg, Hint: aliveHint, Err: err}
	}

	return &CLIError{
		Msg:  "another process is holding the polypkg lock",
		Hint: fmt.Sprintf("if no polypkg command is running, the holder may be an unrelated process locking %s", lockPath),
		Err:  err,
	}
}

// pidAlive reports whether pid refers to a running process.
// It uses signal 0 (no-op probe): nil or EPERM means the process exists;
// ESRCH means it does not.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// buildHolderMsg constructs the human message from lock metadata, including
// only the parts that are actually populated. Called only when the holder PID
// is alive.
func buildHolderMsg(m *lock.Metadata) string {
	var sb strings.Builder
	sb.WriteString("another polypkg command is already running")
	var parts []string
	if m.Command != "" {
		parts = append(parts, m.Command)
	}
	if m.PID > 0 {
		parts = append(parts, fmt.Sprintf("pid %d", m.PID))
	}
	if len(parts) > 0 {
		sb.WriteString(" (")
		sb.WriteString(strings.Join(parts, ", "))
		sb.WriteString(")")
	}
	return sb.String()
}
