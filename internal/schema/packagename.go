package schema

import (
	"fmt"
	"regexp"
)

// PackageNamePattern is the ASCII-slug grammar for a package name: the
// pattern package-v1.json enforces on a recipe's `name`, which every package
// key of a source index must satisfy too.
//
// A package name is not merely a label. Consumers interpolate it into
// filesystem paths (the extract store, mirror staging) and into generated
// YAML keys, so a name carrying a separator, a `..` segment or a YAML
// metacharacter could steer a write outside its directory or forge a key.
const PackageNamePattern = `^[a-zA-Z0-9_-]+$`

var rePackageName = regexp.MustCompile(PackageNamePattern)

// ValidatePackageName reports whether name is a usable package name,
// returning a descriptive error when it is not. Code that takes a package
// name from a fetched document must run it before the name reaches a path.
func ValidatePackageName(name string) error {
	if !rePackageName.MatchString(name) {
		return fmt.Errorf("package name %q is not a valid slug (must match %s)", name, PackageNamePattern)
	}
	return nil
}
