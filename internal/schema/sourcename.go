package schema

import (
	"fmt"
	"regexp"
)

// SourceNamePattern is the ASCII-slug grammar for a repository source name: the
// same `^[a-zA-Z0-9_-]+$` that package-v1.json enforces on a package `name`.
//
// A source name is not merely a label. Producers interpolate it into
// filesystem paths that hold secrets — the encrypted signing key at
// <key-dir>/<source>.key and the build cache at
// <key-dir>/<source>.build-cache.json — so a name carrying a separator or a
// `..` segment would relocate those files outside the directory the operator
// chose. Restricting the name to this charset is what makes that impossible.
const SourceNamePattern = `^[a-zA-Z0-9_-]+$`

var reSourceName = regexp.MustCompile(SourceNamePattern)

// ValidateSourceName reports whether name is a usable repository source name,
// returning a descriptive error when it is not. Callers that accept a source
// name from an operator (a manifest field, a CLI flag) must run this before the
// name reaches any path.
func ValidateSourceName(name string) error {
	if !reSourceName.MatchString(name) {
		return fmt.Errorf("source name %q is not a valid slug (must match %s)", name, SourceNamePattern)
	}
	return nil
}
