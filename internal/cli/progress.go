package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	cterm "github.com/charmbracelet/x/term"
)

// progress writes live phase updates to w. On a TTY it spins a braille
// spinner and rewrites the current line with \r; on a non-TTY it prints each
// distinct (stage, detail) pair once as a plain line. The display is purely
// informational — callers always write results to stdout; progress goes to the
// writer supplied at construction (typically cmd.ErrOrStderr()).
//
// Passing nil for w returns a no-op progress: all methods become safe no-ops.
// Use this under --format json so progress never pollutes a non-TTY stderr.
//
// Concurrency: Update and Done are safe to call from any goroutine. The
// internal ticker goroutine holds the same mutex, so no race is possible.
type progress struct {
	mu       sync.Mutex
	w        io.Writer
	tty      bool
	stage    string
	detail   string
	last     string // last emitted line (non-TTY dedup)
	lastCols int    // rune width of last TTY line rendered (for clear)
	done     bool
	stopCh   chan struct{} // non-nil only on TTY
	doneCh   chan struct{} // closed when ticker exits
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// newProgress creates a progress reporter bound to w. It starts a background
// ticker goroutine when w is a TTY (detected via os.File's fd); otherwise it
// operates in plain-line mode with no goroutine.
//
// When w is nil the returned progress is a no-op: Update and Done do nothing.
func newProgress(w io.Writer) *progress {
	p := &progress{w: w}
	if w == nil {
		return p
	}

	// TTY detection: w must be an *os.File with a terminal fd.
	if f, ok := w.(*os.File); ok && cterm.IsTerminal(f.Fd()) {
		p.tty = true
		p.stopCh = make(chan struct{})
		p.doneCh = make(chan struct{})
		go p.tick()
	}

	return p
}

// Update sets the current stage and detail. On a non-TTY, consecutive
// identical updates are deduplicated. On a TTY, the running ticker picks up
// the new state on its next frame.
func (p *progress) Update(stage, detail string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.w == nil || p.done {
		return
	}
	p.stage = stage
	p.detail = detail

	if !p.tty {
		line := progressLine(stage, detail)
		if line == p.last {
			return
		}
		p.last = line
		fmt.Fprintln(p.w, line)
	}
}

// Done stops the spinner (TTY) or no-ops (non-TTY). After Done returns,
// Update is a no-op. Done is idempotent.
func (p *progress) Done() {
	p.mu.Lock()
	if p.w == nil || p.done {
		p.mu.Unlock()
		return
	}
	p.done = true
	stopCh := p.stopCh
	lastCols := p.lastCols
	p.mu.Unlock()

	if p.tty && stopCh != nil {
		close(stopCh)
		<-p.doneCh
		// Clear exactly as many columns as we last rendered (+ 1 for the spinner
		// frame rune and 1 for the space separator). This avoids wrapping on
		// narrow terminals; clearing to maxCols (100) would wrap at 80 cols.
		clearWidth := lastCols + 2 // spinner rune + space
		if clearWidth < 1 {
			clearWidth = 1
		}
		fmt.Fprintf(p.w, "\r%s\r", strings.Repeat(" ", clearWidth))
	}
}

// tick is the TTY spinner goroutine. It runs until stopCh is closed.
func (p *progress) tick() {
	defer close(p.doneCh)
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()
	frame := 0
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.renderFrame(frame)
			frame = (frame + 1) % len(spinnerFrames)
		}
	}
}

// renderFrame rewrites the current line with spinner frame and the rendered
// stage/detail, and records the line's rune width so Done clears exactly what
// was drawn. Nothing is written (and the recorded width is left alone) until a
// stage has been set.
func (p *progress) renderFrame(frame int) {
	p.mu.Lock()
	stage := p.stage
	detail := p.detail
	p.mu.Unlock()

	if stage == "" {
		return
	}

	// Truncate to keep the terminal line tidy; rune-safe.
	const maxCols = 100
	line := truncateLine(progressLine(stage, detail), maxCols)

	p.mu.Lock()
	p.lastCols = utf8.RuneCountInString(line)
	p.mu.Unlock()

	fmt.Fprintf(p.w, "\r%s %s", spinnerFrames[frame], line)
}

// progressLine renders one progress line. A stage with no detail prints as the
// bare label: keeping the ": " separator would render as "resolving: ", which
// reads as output that got cut off. Both the TTY and non-TTY paths go through
// here so the two stay in agreement, and so the TTY clear width measures the
// line that was actually drawn.
func progressLine(stage, detail string) string {
	if detail == "" {
		return stage
	}
	return stage + ": " + detail
}

// truncateLine returns s truncated to maxCols runes. If truncation is needed
// the last rune is replaced with "…" so the result is always maxCols runes
// wide and valid UTF-8. Strings already within maxCols are returned unchanged.
func truncateLine(s string, maxCols int) string {
	if utf8.RuneCountInString(s) <= maxCols {
		return s
	}
	r := []rune(s)
	return string(r[:maxCols-1]) + "…"
}
