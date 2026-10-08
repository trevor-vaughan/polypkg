package pkglint

import (
	"bytes"
	"sort"

	"github.com/gowebpki/jcs"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

// sarifToolName/Version are PINNED and deliberately decoupled from the polypkg
// binary version so the SARIF predicate is reproducible across releases: the
// signed lint attestation must be byte-identical for the same source
// regardless of which polypkg binary produced it. Bumping the binary must not
// change the predicate. Bump sarifToolVersion only when the rule catalogue
// changes meaning (a rule's semantics change), so a verifier can distinguish
// predicate generations.
const (
	sarifToolName    = "polypkg"
	sarifToolVersion = "1"
)

// SARIF renders findings as canonical, deterministic SARIF 2.1.0: relative
// paths, no timestamps or GUIDs, a pinned tool string, and results sorted by
// (ruleId, path, line). Findings arrive from Lint sorted by (line, ruleID,
// message); here they are re-sorted into SARIF's canonical (ruleId, path, line)
// order, then the serialized report is JCS-canonicalized so key ordering and
// number/string normalization are stable. These exact bytes become the signed
// lint attestation predicate and must be independently reproducible.
//
// No invocation, automationDetails, start/end-time, or GUID-producing methods
// are called: sarif.NewReport/NewRun populate only static fields ($schema,
// version, language, tool), so the marshaled report carries nothing volatile.
func SARIF(res Result) ([]byte, error) {
	report := sarif.NewReport()
	run := sarif.NewRun()
	run.WithTool(sarif.NewTool().WithDriver(
		sarif.NewToolComponent().WithName(sarifToolName).WithVersion(sarifToolVersion)))

	// Register each cited rule once, sorted by id, using the catalogue title as
	// the rule's short description.
	for _, id := range sarifCitedRuleIDs(res) {
		run.Tool.Driver.AddRule(sarif.NewRule(id).WithDescription(rules[id].title))
	}

	for _, f := range sarifSortedFindings(res.Findings) {
		result := sarif.NewRuleResult(f.RuleID).
			WithLevel(string(f.Severity)).
			WithMessage(sarif.NewTextMessage(f.Message))
		// A location is attached only when the finding carries a real 1-based
		// line; a zero Line means "no location" and must not be fabricated.
		if f.Loc.Line > 0 {
			result.AddLocation(sarif.NewLocationWithPhysicalLocation(
				sarif.NewPhysicalLocation().
					WithArtifactLocation(sarif.NewSimpleArtifactLocation(f.File)).
					WithRegion(sarif.NewSimpleRegion(f.Loc.Line, f.Loc.Line))))
		}
		run.AddResult(result)
	}
	report.AddRun(run)

	var buf bytes.Buffer
	if err := report.Write(&buf); err != nil {
		return nil, err
	}
	// JCS gives deterministic object-key ordering and canonical number/string
	// formatting regardless of Go's map iteration or marshal quirks.
	return jcs.Transform(buf.Bytes())
}

// sarifCitedRuleIDs returns the unique rule IDs cited by res, sorted ascending,
// so each ReportingDescriptor is registered exactly once in a stable order.
func sarifCitedRuleIDs(res Result) []string {
	seen := map[string]bool{}
	var ids []string
	for _, f := range res.Findings {
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		ids = append(ids, f.RuleID)
	}
	sort.Strings(ids)
	return ids
}

// sarifSortedFindings returns a copy of findings in SARIF-canonical result
// order: ruleId, then file, then line. Sorting a copy leaves the caller's slice
// (ordered for human output) untouched.
func sarifSortedFindings(findings []Finding) []Finding {
	out := make([]Finding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(a, b int) bool {
		fa, fb := out[a], out[b]
		if fa.RuleID != fb.RuleID {
			return fa.RuleID < fb.RuleID
		}
		if fa.File != fb.File {
			return fa.File < fb.File
		}
		return fa.Loc.Line < fb.Loc.Line
	})
	return out
}
