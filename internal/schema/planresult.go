package schema

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

//go:embed jsonschema/plan-v1.json
var planResultSchemaV1 []byte

// PlanResult is the polypkg.plan/v1 structured output of `polypkg plan`.
type PlanResult struct {
	Schema            string                 `json:"schema"`
	Profile           string                 `json:"profile"`
	Current           *PlanCurrentGen        `json:"current,omitempty"`
	Packages          PlanPackageDiff        `json:"packages"`
	Ownership         PlanOwnershipDiff      `json:"ownership"`
	Drift             []PlanDriftEntry       `json:"drift,omitempty"`
	SkippedRecommends []PlanSkippedRecommend `json:"skipped_recommends,omitempty"`
	Suggests          []PlanSuggestion       `json:"suggests,omitempty"`
	Exit              int                    `json:"exit"`
}

// PlanCurrentGen describes the current generation at plan-time, if any.
type PlanCurrentGen struct {
	Generation  int       `json:"generation"`
	CommittedAt time.Time `json:"committed_at,omitempty"`
}

// PlanPackageDiff mirrors diff.PackageDiff for the JSON wire format. The
// schema package mirrors the diff types rather than importing internal/diff
// to keep schema schema-only.
type PlanPackageDiff struct {
	Added      []ManifestEntry     `json:"added,omitempty"`
	Removed    []ManifestEntry     `json:"removed,omitempty"`
	Upgraded   []PlanVersionChange `json:"upgraded,omitempty"`
	Downgraded []PlanVersionChange `json:"downgraded,omitempty"`
}

// PlanVersionChange is a same-name package whose version moved.
type PlanVersionChange struct {
	Name       string `json:"name"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
	OldHash    string `json:"old_hash,omitempty"`
	NewHash    string `json:"new_hash,omitempty"`
}

// PlanOwnershipDiff mirrors diff.OwnershipDiff for the wire format.
type PlanOwnershipDiff struct {
	Added   []OwnershipEntry      `json:"added,omitempty"`
	Removed []OwnershipEntry      `json:"removed,omitempty"`
	Changed []PlanOwnershipChange `json:"changed,omitempty"`
}

// PlanOwnershipChange is a same-path entry whose Expected differs.
type PlanOwnershipChange struct {
	Path          string   `json:"path"`
	Package       string   `json:"package"`
	Action        string   `json:"action"`
	PriorExpected Expected `json:"prior_expected"`
	NextExpected  Expected `json:"next_expected"`
}

// PlanSkippedRecommend is one Recommends that resolution could not install.
type PlanSkippedRecommend struct {
	Name          string   `json:"name"`
	VersionRange  string   `json:"version_range,omitempty"`
	Reason        string   `json:"reason"`
	RecommendedBy []string `json:"recommended_by,omitempty"`
}

// PlanSuggestion is one advertised Suggests of an installed package.
type PlanSuggestion struct {
	Name         string `json:"name"`
	VersionRange string `json:"version_range,omitempty"`
	SuggestedBy  string `json:"suggested_by,omitempty"`
}

// PlanDriftEntry is one drift observation included in the plan output.
type PlanDriftEntry struct {
	Path   string `json:"path"`
	Action string `json:"action"`
	Reason string `json:"reason"`
	// Remediation is the drift-handling directive (a distinct concept from the
	// package Action above). Renamed from the former "action" key when the
	// package-operation concept adopted that name.
	Remediation  string `json:"remediation,omitempty"`
	Policy       string `json:"policy"`
	PriorHash    string `json:"prior_hash,omitempty"`
	ObservedHash string `json:"observed_hash,omitempty"`
}

// ParsePlanResult reads a JSON plan result from r, validates against the
// v1 JSON Schema, and returns the typed representation.
func ParsePlanResult(r io.Reader) (*PlanResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read plan-result: %w", err)
	}
	if err := validateAgainstSchema(data, planResultSchemaV1, "plan-v1.json"); err != nil {
		return nil, err
	}
	var pr PlanResult
	if err := json.Unmarshal(data, &pr); err != nil {
		return nil, fmt.Errorf("unmarshal plan-result: %w", err)
	}
	return &pr, nil
}
