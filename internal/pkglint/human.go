package pkglint

import (
	"fmt"
	"io"

	"github.com/trevor-vaughan/polypkg/internal/cli/style"
)

// WriteHuman renders findings to w, grouped error-first then warnings. Each
// line reads:
//
//	<sev> <ruleID> <file>:<line>[:<col>]: <message>
//
// A zero line is omitted (never printed as ":0"). With no findings a single
// "clean: no findings" line is written.
func WriteHuman(w io.Writer, res Result) {
	st := style.ForWriter(w)
	if len(res.Findings) == 0 {
		fmt.Fprintln(w, st.Added.Render("clean: no findings"))
		return
	}
	for _, want := range []Severity{SeverityError, SeverityWarning} {
		for _, f := range res.Findings {
			if f.Severity != want {
				continue
			}
			loc := ""
			if f.Loc.Line > 0 {
				loc = fmt.Sprintf(" %s:%d", f.File, f.Loc.Line)
				if f.Loc.Column > 0 {
					loc = fmt.Sprintf(" %s:%d:%d", f.File, f.Loc.Line, f.Loc.Column)
				}
			}
			sev := st.Error.Render(string(f.Severity))
			if want == SeverityWarning {
				sev = st.Hint.Render(string(f.Severity))
			}
			fmt.Fprintf(w, "%s %s%s: %s\n", sev, st.Emph.Render(f.RuleID), loc, f.Message)
		}
	}
}
