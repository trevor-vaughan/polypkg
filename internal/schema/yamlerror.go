package schema

import (
	"errors"
	"regexp"

	"gopkg.in/yaml.v3"
)

// unknownFieldPattern matches yaml.v3's strict-decode complaint about a key
// the target struct does not declare: "line 4: field dependencies not found
// in type schema.Package".
var unknownFieldPattern = regexp.MustCompile(`^(line \d+): field (\S+) not found in type \S+$`)

// plainYAMLDecodeError rewrites yaml.v3's unknown-key complaints so they name
// the key and not the Go type it was decoded into: "line 4: unknown field
// "dependencies"". The result is still a *yaml.TypeError. Any other error is
// returned unchanged.
func plainYAMLDecodeError(err error) error {
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		return err
	}
	msgs := make([]string, len(te.Errors))
	for i, m := range te.Errors {
		msgs[i] = unknownFieldPattern.ReplaceAllString(m, `$1: unknown field "$2"`)
	}
	return &yaml.TypeError{Errors: msgs}
}
