// Package pkglint validates a polypkg package source (polypkg.yaml + content/)
// against structure, identity, action/phase, parameter, and content-reference
// rules. It is the single lint/predicate producer, consumed by `pkg lint`,
// `pkg build`, and (Phase C) `repo build`.
package pkglint

// Severity classifies a finding. Error-severity findings make lint exit
// non-zero and abort `pkg build` before packing.
type Severity string

// The two finding severities: errors block, warnings inform.
const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Loc is a 1-based source position. A zero Line means "no location" — a
// location is omitted, never fabricated, when a field is synthesized or absent.
type Loc struct {
	Line   int
	Column int
}

// Finding is one lint result.
type Finding struct {
	RuleID   string
	Severity Severity
	Message  string
	File     string // relative path, e.g. "polypkg.yaml"; "" if not file-scoped
	Loc      Loc
}

// Result is the full lint outcome for one package source.
type Result struct {
	Findings []Finding
}

// HasErrors reports whether any error-severity finding fired.
func (r Result) HasErrors() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityError {
			return true
		}
	}
	return false
}

// rule carries a rule's fixed metadata (title/description), used by SARIF and
// human output. Messages are per-finding; titles are per-rule.
type rule struct {
	id    string
	title string
}

// rules is the authoritative rule catalogue. SARIF emits a ReportingDescriptor
// per rule actually cited; human output uses titles.
var rules = map[string]rule{
	"PKG000": {"PKG000", "structural error"},
	"PKG001": {"PKG001", "unknown action"},
	"PKG002": {"PKG002", "missing required parameter"},
	"PKG003": {"PKG003", "unknown parameter"},
	"PKG004": {"PKG004", "unknown phase"},
	"PKG005": {"PKG005", "parameter constraint violation"},
	"PKG006": {"PKG006", "dangling content reference"},
	"PKG007": {"PKG007", "non-ASCII-slug identifier"},
	"PKG008": {"PKG008", "case-fold identifier collision"},
	"PKG009": {"PKG009", "file-placing action in non-pre-swap phase"},
	"PKG010": {"PKG010", "invalid parameter value"},
}
