// Package style is the single place ANSI styling originates. Commands use
// semantic styles (Added, Error, Hint…), never colors or escape codes
// directly. Styles degrade to plain text automatically when the writer is
// not a TTY or NO_COLOR is set, so piped/JSON output is never styled.
package style

import (
	"io"

	"github.com/charmbracelet/lipgloss"
)

// Styles is the semantic style set for one output writer.
type Styles struct {
	Added   lipgloss.Style // plan diff "+" lines
	Removed lipgloss.Style // plan diff "-" lines
	Changed lipgloss.Style // plan diff "~" / version-change lines
	Header  lipgloss.Style // section headers
	Error   lipgloss.Style // the "error:" prefix
	Hint    lipgloss.Style // the "hint: …" line
	Emph    lipgloss.Style // inline emphasis (names, ids)
}

// ForWriter binds styles to w's terminal capabilities. lipgloss's renderer
// detects TTY-ness and honors NO_COLOR; non-TTY writers get no-op styles.
func ForWriter(w io.Writer) Styles {
	r := lipgloss.NewRenderer(w)
	return Styles{
		Added:   r.NewStyle().Foreground(lipgloss.Color("2")), // green
		Removed: r.NewStyle().Foreground(lipgloss.Color("1")), // red
		Changed: r.NewStyle().Foreground(lipgloss.Color("3")), // yellow
		Header:  r.NewStyle().Bold(true),
		Error:   r.NewStyle().Foreground(lipgloss.Color("1")).Bold(true),
		Hint:    r.NewStyle().Faint(true),
		Emph:    r.NewStyle().Bold(true),
	}
}
