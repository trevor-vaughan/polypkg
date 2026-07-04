package schema

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

//go:embed jsonschema/status-v1.json
var statusResultSchemaV1 []byte

// StatusResult is the polypkg.status/v1 structured output of
// `polypkg status --format json`. The PlanDriftEntry type used in the
// Drift field is shared with PlanResult (defined in planresult.go).
type StatusResult struct {
	Schema    string             `json:"schema"`
	Current   *StatusCurrentGen  `json:"current,omitempty"`
	Retained  []StatusGenSummary `json:"retained"`
	Drift     []PlanDriftEntry   `json:"drift,omitempty"`
	GCPreview *StatusGCPreview   `json:"gc_preview,omitempty"`
}

// StatusCurrentGen describes the active generation.
type StatusCurrentGen struct {
	Generation int       `json:"generation"`
	Profile    string    `json:"profile,omitempty"`
	AppliedAt  time.Time `json:"applied_at,omitempty"`
}

// StatusGenSummary is one row of the retained-generation list.
type StatusGenSummary struct {
	ID           int       `json:"id"`
	CommittedAt  time.Time `json:"committed_at"`
	Pinned       bool      `json:"pinned,omitempty"`
	PinnedReason string    `json:"pinned_reason,omitempty"`
	IsCurrent    bool      `json:"is_current,omitempty"`
	BytesOnDisk  int64     `json:"bytes_on_disk,omitempty"`
}

// StatusGCPreview describes what the next opportunistic GC would do under
// the default retention policy.
type StatusGCPreview struct {
	WouldRemove []int `json:"would_remove,omitempty"`
	WouldKeep   []int `json:"would_keep,omitempty"`
}

// ParseStatusResult reads a JSON status result from r, validates against
// the v1 JSON Schema, and returns the typed representation.
func ParseStatusResult(r io.Reader) (*StatusResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read status-result: %w", err)
	}
	if err := validateAgainstSchema(data, statusResultSchemaV1, "status-v1.json"); err != nil {
		return nil, err
	}
	var sr StatusResult
	if err := json.Unmarshal(data, &sr); err != nil {
		return nil, fmt.Errorf("unmarshal status-result: %w", err)
	}
	if sr.Retained == nil {
		sr.Retained = []StatusGenSummary{}
	}
	return &sr, nil
}
