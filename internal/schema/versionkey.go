package schema

import "github.com/Masterminds/semver/v3"

// VersionKey identifies a semantic version up to semver equality, so a map
// keyed by it finds an earlier spelling of a version in constant time: two
// versions have one key exactly when semver.Version.Equal holds. Equal
// ignores build metadata and the spelling (a "v" prefix, "1.0" for "1.0.0"),
// and compares prerelease identifiers part by part, numeric parts as numbers.
// The parser refuses a numeric identifier with a leading zero, so equal
// prereleases are equal strings.
type VersionKey struct {
	Major, Minor, Patch uint64
	Prerelease          string
}

// VersionKeyOf returns v's VersionKey.
func VersionKeyOf(v *semver.Version) VersionKey {
	return VersionKey{Major: v.Major(), Minor: v.Minor(), Patch: v.Patch(), Prerelease: v.Prerelease()}
}
