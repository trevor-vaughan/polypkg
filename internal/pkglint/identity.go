package pkglint

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var reSlug = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// relationFields is the closed set of relation-bearing fields, used for both
// slug and case-fold checks and for location lookup by field name.
var relationFields = []string{"depends", "recommends", "suggests", "provides", "conflicts", "obsoletes"}

// checkIdentity enforces PKG007 (ASCII slug on every relation name) and PKG008
// (case-fold collisions across the package name + relation names). The package
// name is schema-guaranteed to be a slug, so it needs no PKG007, but it is
// included in the case-fold pool. Name-like PARAM identifiers are slug-checked
// in the params layer via ParamSpec.Pattern.
func checkIdentity(pkg *schema.Package, idx *docIndex) []Finding {
	var out []Finding

	// Collect (identifier, ruleLoc) for case-fold analysis.
	type ident struct {
		value string
		loc   Loc
	}
	var idents []ident

	// package name: schema already guarantees the slug, but include it in the
	// case-fold pool.
	idents = append(idents, ident{pkg.Name, loc(mapValue(idx.root, "name"))})

	relSlices := map[string][]schema.Relation{
		"depends": pkg.Depends, "recommends": pkg.Recommends, "suggests": pkg.Suggests,
		"provides": pkg.Provides, "conflicts": pkg.Conflicts, "obsoletes": pkg.Obsoletes,
	}
	for _, field := range relationFields {
		for j, r := range relSlices[field] {
			rloc := loc(idx.relationNode(field, j))
			if !reSlug.MatchString(r.Name) {
				out = append(out, Finding{
					RuleID: "PKG007", Severity: SeverityError, File: "polypkg.yaml", Loc: rloc,
					Message: fmt.Sprintf("relation name %q in %q is not an ASCII slug (^[a-zA-Z0-9_-]+$)", r.Name, field),
				})
			}
			idents = append(idents, ident{r.Name, rloc})
		}
	}

	// PKG008 case-fold collisions: two DISTINCT identifiers equal under
	// strings.ToLower but not byte-equal. The finding fires on the later one.
	seen := map[string]ident{}
	for _, id := range idents {
		key := strings.ToLower(id.value)
		if prev, ok := seen[key]; ok {
			if prev.value != id.value {
				out = append(out, Finding{
					RuleID: "PKG008", Severity: SeverityError, File: "polypkg.yaml", Loc: id.loc,
					Message: fmt.Sprintf("identifier %q collides case-insensitively with %q", id.value, prev.value),
				})
			}
			continue
		}
		seen[key] = id
	}
	return out
}
