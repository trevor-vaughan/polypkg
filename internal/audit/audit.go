// Package audit provides polypkg's audit log writer (JSON Lines file
// sink). M2 will add the journald sink alongside this one.
package audit

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sync"
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

// FileWriter writes audit events as JSON Lines to a file.
type FileWriter struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// NewFileWriter opens (creates if necessary) the audit log file at path.
func NewFileWriter(path string) (*FileWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir audit parent: %w", err)
	}
	clean := filepath.Clean(path)
	f, err := os.OpenFile(clean, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &FileWriter{f: f, path: clean}, nil
}

// Write appends one event to the log.
func (w *FileWriter) Write(e Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	data = append(data, '\n')
	if _, err := w.f.Write(data); err != nil {
		return fmt.Errorf("write audit: %w", err)
	}
	return nil
}

// Close closes the audit log file.
func (w *FileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
