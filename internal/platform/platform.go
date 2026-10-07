// Package platform names the operating system and CPU architecture a package
// artifact is built for: "<os>/<arch>[/<variant>]" in Go's GOOS/GOARCH
// vocabulary, each segment lower-case ASCII letters and digits.
//
// Two strictnesses apply, deliberately different. A consumer (index parsing,
// the catalog) accepts any well-formed platform of two or three segments, so
// an index naming a platform a later polypkg understands is still readable;
// the entry simply never matches this host. A producer (pkg lint, repo build)
// accepts only an <os>/<arch> pair the Go toolchain that built polypkg
// supports, so a typo like "linux/amd46" is an error rather than an entry no
// host ever selects.
package platform

import (
	"fmt"
	"regexp"
	"runtime"
	"slices"
	"strings"
)

//go:generate go run gen_known.go

// Any is the token a signed artifact claim uses for a platform-agnostic
// artifact ("platform=any"). Index entries and recipes express the same thing
// by omitting the platform. The grammar cannot produce it: it has no "/".
const Any = "any"

// Display renders a stored platform for output: p itself, or Any for a
// platform-agnostic artifact, which indexes and manifests store as "".
func Display(p string) string {
	if p == "" {
		return Any
	}
	return p
}

// Pattern is the consumer grammar. index-v3.json's entry "platform" and
// package-v1.json's "platform" carry the same pattern; schema tests pin both
// to this constant.
const Pattern = `^[a-z0-9]+/[a-z0-9]+(/[a-z0-9]+)?$`

var reConsumer = regexp.MustCompile(Pattern)

// Host is the platform of the running binary. There is no normalisation
// layer: an entry matches this host only when it is byte-equal to Host().
func Host() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

// ValidateConsumer reports whether p is a well-formed platform: two or three
// "/"-separated segments, each one or more of [a-z0-9]. It is the check for a
// platform read from a fetched document; it does not ask whether any Go
// toolchain supports p.
func ValidateConsumer(p string) error {
	if !reConsumer.MatchString(p) {
		return fmt.Errorf("platform %q is not <os>/<arch>[/<variant>] with each segment lower-case letters and digits", p)
	}
	return nil
}

// ValidateProducer reports whether p may be published: it must pass
// ValidateConsumer, have exactly two segments (no variant; variant matching
// does not exist yet), and be an <os>/<arch> pair `go tool dist list` names
// for the toolchain that built polypkg.
func ValidateProducer(p string) error {
	if err := ValidateConsumer(p); err != nil {
		return err
	}
	if strings.Count(p, "/") != 1 {
		return fmt.Errorf("platform %q has a variant segment; only <os>/<arch> can be published", p)
	}
	if _, found := slices.BinarySearch(knownPorts, p); !found {
		return fmt.Errorf("platform %q is not a Go port (`go tool dist list` names the valid <os>/<arch> pairs)", p)
	}
	return nil
}
