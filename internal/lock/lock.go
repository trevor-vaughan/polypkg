// Package lock provides per-scope advisory file locking for polypkg. It records
// holder metadata (PID, hostname, epoch) for stale-lock recovery, which is not
// implemented: acquisition fails fast, with an optional wait.
package lock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Options controls lock acquisition behavior.
type Options struct {
	Wait        bool
	WaitTimeout time.Duration
	TxID        string
	Command     string
}

// Metadata describes the current lock holder.
type Metadata struct {
	PID       int       `json:"pid"`
	Hostname  string    `json:"hostname"`
	Epoch     int64     `json:"epoch"`
	TxID      string    `json:"tx_id"`
	Command   string    `json:"command"`
	StartedAt time.Time `json:"started_at"`
}

// Lock is an acquired filesystem lock.
type Lock struct {
	path string
	f    *os.File
}

// Acquire takes an exclusive lock at path, applying contention behavior per opts.
func Acquire(ctx context.Context, path string, opts Options) (*Lock, error) {
	clean := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(clean), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir lock parent: %w", err)
	}
	f, err := os.OpenFile(clean, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	//nolint:gosec // G115: int and uintptr are the same width on every platform Go
	// supports, and Fd returns either a small non-negative descriptor or
	// ^uintptr(0), which lands on -1 and flock rejects with EBADF. Nothing truncates.
	fd := int(f.Fd())
	if err := acquireFlock(ctx, fd, opts); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := writeMetadata(f, opts); err != nil {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = f.Close()
		return nil, err
	}
	return &Lock{path: clean, f: f}, nil
}

// acquireFlock applies the lock, honoring fail-fast, blocking-wait, ctx
// cancellation, and an optional WaitTimeout.
func acquireFlock(ctx context.Context, fd int, opts Options) error {
	err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.EWOULDBLOCK) {
		return fmt.Errorf("flock: %w", err)
	}
	if !opts.Wait {
		return fmt.Errorf("lock is held by another process")
	}
	var timeout <-chan time.Time
	if opts.WaitTimeout > 0 {
		timer := time.NewTimer(opts.WaitTimeout)
		defer timer.Stop()
		timeout = timer.C
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("lock wait cancelled: %w", ctx.Err())
		case <-timeout:
			return fmt.Errorf("lock wait timed out after %s", opts.WaitTimeout)
		case <-ticker.C:
			ferr := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
			if ferr == nil {
				return nil
			}
			if !errors.Is(ferr, syscall.EWOULDBLOCK) {
				return fmt.Errorf("flock: %w", ferr)
			}
		}
	}
}

// writeMetadata writes lock holder metadata to f.
func writeMetadata(f *os.File, opts Options) error {
	host, _ := os.Hostname()
	meta := Metadata{
		PID:       os.Getpid(),
		Hostname:  host,
		Epoch:     time.Now().Unix(),
		TxID:      opts.TxID,
		Command:   opts.Command,
		StartedAt: time.Now().UTC(),
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	if err := f.Truncate(0); err != nil {
		return fmt.Errorf("truncate lock: %w", err)
	}
	if _, err := f.WriteAt(data, 0); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	return nil
}

// Release releases the lock and closes the file.
func (l *Lock) Release() error {
	if l.f == nil {
		return nil
	}
	//nolint:gosec // G115: same int/uintptr width parity as in Acquire.
	if err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("unflock: %w", err)
	}
	if err := l.f.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	l.f = nil
	return nil
}

// ReadMetadata reads the lock metadata without acquiring the lock.
func ReadMetadata(path string) (*Metadata, error) {
	clean := filepath.Clean(path)
	data, err := os.ReadFile(clean)
	if err != nil {
		return nil, fmt.Errorf("read lock: %w", err)
	}
	var m Metadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}
	return &m, nil
}
