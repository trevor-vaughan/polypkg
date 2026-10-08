package schema

import (
	"strings"
	"testing"
)

func TestCaseFoldCollision(t *testing.T) {
	entry := func(version, plat string) IndexEntry { return IndexEntry{Version: version, Platform: plat} }
	cases := []struct {
		name     string
		packages map[string][]IndexEntry
		wantErr  string
	}{
		{
			name: "distinct names and versions",
			packages: map[string][]IndexEntry{
				"tool":  {entry("1.0.0", ""), entry("1.1.0-rc.1", "")},
				"other": {entry("1.0.0", "")},
			},
		},
		{
			name: "one version for several platforms",
			packages: map[string][]IndexEntry{
				"tool": {entry("1.0.0-RC1", "linux/amd64"), entry("1.0.0-RC1", "darwin/arm64")},
			},
		},
		{
			name: "names that differ only in case",
			packages: map[string][]IndexEntry{
				"tool": {entry("1.0.0", "")},
				"Tool": {entry("2.0.0", "")},
			},
			wantErr: `package names "Tool" and "tool" differ only in letter case`,
		},
		{
			name: "versions that differ only in case",
			packages: map[string][]IndexEntry{
				"tool": {entry("1.0.0-rc1", "linux/amd64"), entry("1.0.0-RC1", "darwin/arm64")},
			},
			wantErr: `package "tool" versions "1.0.0-rc1" and "1.0.0-RC1" differ only in letter case`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CaseFoldCollision(&Index{Packages: tc.packages})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("CaseFoldCollision = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("CaseFoldCollision = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}
