// Package audit provides polypkg's audit log writer (JSON Lines file
// sink). M2 will add the journald sink alongside this one.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Event is one structured audit log entry.
type Event struct {
	Schema string         `json:"schema"`
	Ts     time.Time      `json:"ts"`
	Scope  string         `json:"scope"`
	TxID   string         `json:"tx_id"`
	Event  string         `json:"event"`
	Actor  string         `json:"actor,omitempty"`
	Fields map[string]any `json:"-"`
}

// MarshalJSON merges the standard fields with the event-specific fields.
func (e Event) MarshalJSON() ([]byte, error) {
	if e.Ts.IsZero() {
		e.Ts = time.Now().UTC()
	}
	if e.Schema == "" {
		e.Schema = "polypkg.audit/v1"
	}
	out := map[string]any{
		"schema": e.Schema,
		"ts":     e.Ts.Format(time.RFC3339Nano),
		"scope":  e.Scope,
		"tx_id":  e.TxID,
		"event":  e.Event,
	}
	if e.Actor != "" {
		out["actor"] = e.Actor
	}
	maps.Copy(out, e.Fields)
	return json.Marshal(out)
}

// Writer is the audit log sink interface.
type Writer interface {
	Write(e Event) error
	Close() error
}

// Rotation bounds the audit log's disk use. Before an append that would grow
// the log past MaxBytes, the log is renamed to <path>.1 (older rotations shift
// up to <path>.<Keep> and the oldest is dropped) and a fresh log is started.
// An event is never split: an empty log takes the event whatever its size.
type Rotation struct {
	MaxBytes int64
	Keep     int
}

// DefaultRotation caps the live log at 10 MiB and keeps three rotated files,
// so the audit trail never takes more than ~40 MiB of the state dir. An event
// is a few hundred bytes, so one file holds tens of thousands of applies,
// gc runs, and pins — years of workstation history — while staying small
// enough to grep and to copy off the machine.
var DefaultRotation = Rotation{MaxBytes: 10 << 20, Keep: 3}

// FileWriter writes audit events as JSON Lines to a file, rotating it per its
// Rotation.
//
// Every polypkg process appends to the same file, and not all of them hold
// apply.lock while they do (applyProfile records attestation.gate_off and
// metadata.expiry_graced before the runner takes it), so writes and rotations
// are serialised across processes by an flock on <path>.lock. The lock is a
// sidecar because rotation renames the log itself: two processes locking
// "audit.log" could each hold a different inode.
type FileWriter struct {
	mu   sync.Mutex
	f    *os.File
	lock *os.File
	path string
	rot  Rotation
}

// NewFileWriter opens (creates if necessary) the audit log file at path,
// rotating per DefaultRotation.
func NewFileWriter(path string) (*FileWriter, error) {
	return NewRotatingFileWriter(path, DefaultRotation)
}

// NewRotatingFileWriter opens (creates if necessary) the audit log file at
// path and its <path>.lock sidecar, rotating per rot. It fails if the lock
// sidecar cannot be created or opened, because writes cannot be serialised
// across processes without it.
func NewRotatingFileWriter(path string, rot Rotation) (*FileWriter, error) {
	if rot.MaxBytes <= 0 || rot.Keep < 1 {
		return nil, fmt.Errorf("invalid audit log rotation: max bytes %d, keep %d (both must be positive)", rot.MaxBytes, rot.Keep)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir audit parent: %w", err)
	}
	clean := filepath.Clean(path)
	lf, err := os.OpenFile(filepath.Clean(clean+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit lock: %w", err)
	}
	f, err := os.OpenFile(clean, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		_ = lf.Close()
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &FileWriter{f: f, lock: lf, path: clean, rot: rot}, nil
}

// Write appends one event to the log, rotating first when the event would
// push the log past the rotation threshold. A failed rotation, or a failure
// to reopen the log after another writer rotated it, is logged and the event
// is appended to the file already open: losing an audit record is worse than
// a log that outgrew its cap or landed in a rotated file.
func (w *FileWriter) Write(e Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return errors.New("write audit: log is closed")
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	data = append(data, '\n')

	//nolint:gosec // G115: int and uintptr are the same width on every platform Go
	// supports, and Fd returns a small non-negative descriptor for an open file.
	lockFD := int(w.lock.Fd())
	if err := syscall.Flock(lockFD, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock audit log: %w", err)
	}
	defer func() { _ = syscall.Flock(lockFD, syscall.LOCK_UN) }()

	if err := w.followRename(); err != nil {
		// The held handle may now be a rotated file, so rotating from it would
		// shift files another writer owns; append to it instead.
		slog.Warn("audit log could not follow another writer's rotation; appending to the file already open", "path", w.path, "error", err)
	} else if err := w.rotateIfFull(int64(len(data))); err != nil {
		slog.Warn("audit log rotation failed; appending to the current log", "path", w.path, "error", err)
	}
	if _, err := w.f.Write(data); err != nil {
		return fmt.Errorf("write audit: %w", err)
	}
	return nil
}

// followRename re-points w at the file now named w.path when another writer
// rotated the log since w opened it; otherwise w would keep appending to what
// is now <path>.1. Callers hold the sidecar flock.
func (w *FileWriter) followRename() error {
	open, err := w.f.Stat()
	if err != nil {
		return fmt.Errorf("stat audit log: %w", err)
	}
	named, err := os.Stat(w.path)
	if err == nil && os.SameFile(open, named) {
		return nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat audit log: %w", err)
	}
	return w.reopen()
}

// rotateIfFull rotates the log when appending next more bytes would push it
// past w.rot.MaxBytes. An empty log is never rotated, so an event larger than
// the cap still lands whole in a file of its own. Callers hold the sidecar
// flock.
func (w *FileWriter) rotateIfFull(next int64) error {
	info, err := w.f.Stat()
	if err != nil {
		return fmt.Errorf("stat audit log: %w", err)
	}
	if info.Size() == 0 || info.Size()+next <= w.rot.MaxBytes {
		return nil
	}
	for i := w.rot.Keep - 1; i >= 1; i-- {
		err := os.Rename(fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("rotate audit log: %w", err)
		}
	}
	if err := os.Rename(w.path, w.path+".1"); err != nil {
		return fmt.Errorf("rotate audit log: %w", err)
	}
	return w.reopen()
}

// reopen swaps w.f for a fresh append handle on w.path, creating the file
// after a rotation moved it away. On failure w.f is left untouched, so the
// next append still lands somewhere on disk.
func (w *FileWriter) reopen() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("reopen audit log: %w", err)
	}
	_ = w.f.Close() // unbuffered writes: every byte is already in the kernel
	w.f = f
	return nil
}

// Close closes the audit log file and its lock sidecar. It is idempotent.
func (w *FileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := errors.Join(w.f.Close(), w.lock.Close())
	w.f, w.lock = nil, nil
	return err
}
