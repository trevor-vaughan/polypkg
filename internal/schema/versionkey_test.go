package schema

import (
	"testing"

	"github.com/Masterminds/semver/v3"
)

// TestVersionKeyOfMatchesSemverEquality pins that two versions have one key
// exactly when semver.Version.Equal holds, over spellings that differ in a
// "v" prefix, missing segments, build metadata and prerelease identifiers.
func TestVersionKeyOfMatchesSemverEquality(t *testing.T) {
	spellings := []string{
		"1.0.0", "1.0", "1", "v1.0.0", "1.0.0+a", "1.0.0+b",
		"1.0.0-rc.1", "1.0.0-rc.1+x", "1.0.0-rc.01x", "1.0.0-rc.10", "1.0.0-RC.1",
		"1.0.0-1", "1.0.0-1.0", "1.0.0-alpha", "1.0.0-alpha.beta", "1.0.1", "2.0.0",
		"1.0.0-18446744073709551616", "1.0.0-18446744073709551617",
	}
	versions := make([]*semver.Version, len(spellings))
	for i, s := range spellings {
		v, err := semver.NewVersion(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		versions[i] = v
	}
	for i, a := range versions {
		for j, b := range versions {
			if got, want := VersionKeyOf(a) == VersionKeyOf(b), a.Equal(b); got != want {
				t.Errorf("%q and %q: keys equal = %v, Equal = %v", spellings[i], spellings[j], got, want)
			}
		}
	}
}
