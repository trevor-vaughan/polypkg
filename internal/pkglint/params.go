package pkglint

import (
	"fmt"
	"math"
	"regexp"
	"strconv"

	"github.com/trevor-vaughan/polypkg/internal/action"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// validPhases is the closed set of the 6 lifecycle phases.
var validPhases = map[string]bool{
	"pre-place": true, "post-place": true, "pre-activate": true,
	"post-activate": true, "pre-deactivate": true, "post-deactivate": true,
}

// checkActionsAndParams runs the action/phase layer (PKG001/PKG004/PKG009) and the
// param layer (PKG002/PKG003/PKG005/PKG007-on-params/PKG010) for every action.
//
// PKG001 (unknown action) and PKG004 (unknown phase) are registry-driven checks
// that are, in practice, unreachable through Lint: the package JSON schema binds
// action and phase to closed enums (action bound to action.Registry), so ParsePackage
// rejects an unknown value as a structural PKG000 first. They remain here as the
// linter defensively consulting the registry and are tested at the layer level
// (see Decision 6).
func checkActionsAndParams(pkg *schema.Package, idx *docIndex) []Finding {
	var out []Finding
	for i, v := range pkg.Actions {
		vloc := loc(idx.actionNode(i))

		if !validPhases[v.Phase] {
			out = append(out, Finding{
				RuleID: "PKG004", Severity: SeverityError, File: "polypkg.yaml", Loc: vloc,
				Message: fmt.Sprintf("unknown phase %q (want one of pre-place, post-place, pre-activate, post-activate, pre-deactivate, post-deactivate)", v.Phase),
			})
		}

		spec, ok := action.Registry[v.Action]
		if !ok {
			out = append(out, Finding{
				RuleID: "PKG001", Severity: SeverityError, File: "polypkg.yaml", Loc: vloc,
				Message: fmt.Sprintf("unknown action %q", v.Action),
			})
			continue // no spec ⇒ cannot check params/phase-placement
		}

		if spec.FilePlacing && validPhases[v.Phase] && !action.IsPreSwapPhase(v.Phase) {
			out = append(out, Finding{
				RuleID: "PKG009", Severity: SeverityError, File: "polypkg.yaml", Loc: vloc,
				Message: fmt.Sprintf("file-placing action %q must run in a pre-swap phase (pre-place, post-place, pre-activate), not %q", v.Action, v.Phase),
			})
		}

		out = append(out, checkParams(spec, v, i, idx)...)
	}
	return out
}

// checkParams validates one action's params against its registry Spec:
// PKG003 unknown, PKG002 missing-required, PKG010 bad literal (enum/mode/int/
// string list), PKG007 non-slug name-like value, PKG005 constraint violations.
// Params whose value is a schema.StarlarkExpr are skipped for value/pattern
// checks, except that a list param given one is PKG010: !starlark computes a
// string, never a list.
func checkParams(spec action.Spec, v schema.PackageAction, i int, idx *docIndex) []Finding {
	var out []Finding
	declared := map[string]action.ParamSpec{}
	for _, p := range spec.Params {
		declared[p.Name] = p
	}

	// Params named by an Unsupported constraint are "known-but-rejected": they
	// are owned by PKG005 ("not supported"), which is more actionable than
	// PKG003 ("no parameter"). Suppress the redundant PKG003 for them.
	unsupported := map[string]bool{}
	for _, c := range spec.Constraints {
		if c.Kind == action.Unsupported {
			for _, o := range c.Others {
				unsupported[o] = true
			}
		}
	}

	// PKG003 unknown params.
	for name := range v.Params {
		if _, ok := declared[name]; !ok && !unsupported[name] {
			out = append(out, Finding{
				RuleID: "PKG003", Severity: SeverityError, File: "polypkg.yaml",
				Loc:     loc(idx.paramNode(i, name)),
				Message: fmt.Sprintf("action %q has no parameter %q", v.Action, name),
			})
		}
	}

	// PKG002 missing required, PKG010 bad value, PKG007 bad name-like value.
	for _, p := range spec.Params {
		raw, present := v.Params[p.Name]
		if !present {
			if p.Required {
				out = append(out, Finding{
					RuleID: "PKG002", Severity: SeverityError, File: "polypkg.yaml",
					Loc:     loc(idx.actionNode(i)),
					Message: fmt.Sprintf("action %q is missing required parameter %q", v.Action, p.Name),
				})
			}
			continue
		}
		ploc := loc(idx.paramNode(i, p.Name))
		if _, computed := raw.(schema.StarlarkExpr); computed {
			// !starlark values are not literals. A computed value is always a
			// string, so a list param can never be computed.
			if p.Kind == action.KindStringList {
				out = append(out, Finding{RuleID: "PKG010", Severity: SeverityError, File: "polypkg.yaml", Loc: ploc,
					Message: fmt.Sprintf("%s cannot be computed by !starlark; it must be a literal list", p.Name)})
			}
			continue
		}
		if msg := checkValue(p, raw); msg != "" {
			out = append(out, Finding{RuleID: "PKG010", Severity: SeverityError, File: "polypkg.yaml", Loc: ploc, Message: msg})
		}
		if p.Pattern != "" {
			if s, ok := raw.(string); ok && !slugRe(p.Pattern).MatchString(s) {
				out = append(out, Finding{
					RuleID: "PKG007", Severity: SeverityError, File: "polypkg.yaml", Loc: ploc,
					Message: fmt.Sprintf("parameter %q value %q is not an ASCII slug (%s)", p.Name, s, p.Pattern),
				})
			}
		}
	}

	out = append(out, checkConstraints(spec, v, i, idx)...)
	return out
}

// checkValue validates a literal param value against its Kind; returns a
// human message on violation, "" when ok.
func checkValue(p action.ParamSpec, raw any) string {
	switch p.Kind {
	case action.KindEnum:
		s, _ := raw.(string)
		for _, e := range p.Enum {
			if s == e {
				return ""
			}
		}
		return fmt.Sprintf("parameter %q value %q is not one of %v", p.Name, raw, p.Enum)
	case action.KindMode:
		s, ok := raw.(string)
		if !ok || !reOctalMode.MatchString(s) {
			return fmt.Sprintf("parameter %q value %v is not an octal mode (e.g. 0o755)", p.Name, raw)
		}
		if err := action.CheckMode(s); err != nil {
			return fmt.Sprintf("parameter %q value %q %v", p.Name, s, err)
		}
	case action.KindInt:
		switch t := raw.(type) {
		case int, int64:
		case float64:
			// A fractional literal decodes as float64. (.inf and .nan never
			// get here: the structural layer cannot marshal them.)
			if t != math.Trunc(t) {
				return fmt.Sprintf("parameter %q value %v is not an integer", p.Name, raw)
			}
		case string:
			if _, err := strconv.Atoi(t); err != nil {
				return fmt.Sprintf("parameter %q value %q is not an integer", p.Name, raw)
			}
		default:
			return fmt.Sprintf("parameter %q value %v is not an integer", p.Name, raw)
		}
	case action.KindStringList:
		list, ok := raw.([]any)
		if !ok {
			return fmt.Sprintf("parameter %q value %v is not a list of strings", p.Name, raw)
		}
		for _, e := range list {
			if _, ok := e.(string); !ok {
				return fmt.Sprintf("parameter %q entry %v is not a string", p.Name, e)
			}
		}
	}
	return "" // KindString / KindPath: any string; deeper path checks are the content layer
}

// checkConstraints enforces the cross-param constraint vocabulary (PKG005).
func checkConstraints(spec action.Spec, v schema.PackageAction, i int, idx *docIndex) []Finding {
	var out []Finding
	has := func(name string) bool { _, ok := v.Params[name]; return ok }
	add := func(msg string) {
		out = append(out, Finding{RuleID: "PKG005", Severity: SeverityError, File: "polypkg.yaml", Loc: loc(idx.actionNode(i)), Message: msg})
	}
	for _, c := range spec.Constraints {
		switch c.Kind {
		case action.RequiredWith:
			if has(c.Param) {
				for _, o := range c.Others {
					if !has(o) {
						add(fmt.Sprintf("action %q: parameter %q requires %q", v.Action, c.Param, o))
					}
				}
			}
		case action.ForbiddenWith:
			if has(c.Param) {
				for _, o := range c.Others {
					if has(o) {
						add(fmt.Sprintf("action %q: parameter %q cannot be combined with %q", v.Action, c.Param, o))
					}
				}
			}
		case action.RequiredWithout:
			if !has(c.Param) {
				for _, o := range c.Others {
					if !has(o) {
						add(fmt.Sprintf("action %q: without %q, parameter %q is required", v.Action, c.Param, o))
					}
				}
			}
		case action.Unsupported:
			for _, o := range c.Others {
				if has(o) {
					add(fmt.Sprintf("action %q: parameter %q is not supported", v.Action, o))
				}
			}
		}
	}
	return out
}

var reOctalMode = regexp.MustCompile(`^0o?[0-7]{3,4}$`)

// slugRe compiles a name pattern from a ParamSpec.
func slugRe(pat string) *regexp.Regexp { return regexp.MustCompile(pat) }
