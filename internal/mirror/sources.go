package mirror

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// SourceSpec is one upstream source in a --sources-file: what to pull and how to
// verify it. Packages selects within that source (empty ⇒ latest of every
// package), so a multi-source pull can say "foo from A, bar from B". URL and
// TrustRoot are passed verbatim to mirror.Pull, exactly as the single-source
// --source-url / --trust-root flags are (operator uses absolute or cwd-relative
// paths).
type SourceSpec struct {
	URL               string   `yaml:"url"`
	TrustRoot         string   `yaml:"trust_root"`
	SourceType        string   `yaml:"source_type,omitempty"`
	SourceName        string   `yaml:"source_name,omitempty"`
	AcceptExpiryUntil string   `yaml:"accept_expiry_until,omitempty"`
	Packages          []string `yaml:"packages,omitempty"`
}

// ParseSourcesFile reads a YAML list of SourceSpec from path. Every entry must
// set url and trust_root; an empty list is rejected. Used by `polypkg mirror
// pull --sources-file` to fan out one Pull per upstream.
func ParseSourcesFile(path string) ([]SourceSpec, error) {
	raw, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // G304: operator-supplied sources file path
	if err != nil {
		return nil, fmt.Errorf("read sources file: %w", err)
	}
	var specs []SourceSpec
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&specs); err != nil {
		return nil, fmt.Errorf("parse sources file: %w", err)
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("sources file %s lists no sources", path)
	}
	for i := range specs {
		if specs[i].URL == "" {
			return nil, fmt.Errorf("sources file entry %d: url is required", i+1)
		}
		if specs[i].TrustRoot == "" {
			return nil, fmt.Errorf("sources file entry %d (%s): trust_root is required", i+1, specs[i].URL)
		}
	}
	return specs, nil
}
