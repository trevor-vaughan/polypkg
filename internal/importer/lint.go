package importer

import (
	"fmt"

	"github.com/trevor-vaughan/polypkg/internal/pkglint"
)

// PkgLint is the Options.Lint `pkg import` uses: polypkg's package-source
// linter run in-process, each finding rendered as
// "<severity> <rule> <file>[:<line>]: <message>". An import refuses on any
// finding, warnings included.
func PkgLint(dir string) ([]string, error) {
	res, err := pkglint.Lint(dir)
	if err != nil {
		return nil, err
	}
	findings := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		where := f.File
		if f.Loc.Line > 0 {
			where = fmt.Sprintf("%s:%d", f.File, f.Loc.Line)
		}
		findings = append(findings, fmt.Sprintf("%s %s %s: %s", f.Severity, f.RuleID, where, f.Message))
	}
	return findings, nil
}
