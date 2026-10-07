package cli

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"

	cterm "github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"
)

// terminalInput is a stdin that reports for itself whether it is a terminal.
// A real stdin is an *os.File and is asked with an ioctl instead; tests wire
// a reader implementing this to answer a confirmation prompt in-process.
type terminalInput interface {
	io.Reader
	IsTerminal() bool
}

// isInteractive reports whether the command's stdin is a terminal, so a
// confirmation prompt can be shown and answered. A redirected stdin (a pipe,
// a file, /dev/null) is not one, even when it is a character device: it
// would answer the prompt with whatever it happens to hold.
func isInteractive(cmd *cobra.Command) bool {
	switch in := cmd.InOrStdin().(type) {
	case terminalInput:
		return in.IsTerminal()
	case *os.File:
		return cterm.IsTerminal(in.Fd())
	default:
		return false
	}
}

// maxAnswerBytes bounds the read of a y/N answer. A stdin that never sends a
// newline (/dev/zero, a runaway pipe) is cut off here instead of being read
// without end.
const maxAnswerBytes = 64

// readYes reads one answer line from in and reports whether it is "y" or "Y"
// (surrounding spaces ignored). Anything else declines: another word, an
// empty line, EOF, or maxAnswerBytes with no newline.
func readYes(in io.Reader) (bool, error) {
	line, err := bufio.NewReader(io.LimitReader(in, maxAnswerBytes)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	line = strings.TrimSpace(line)
	return line == "y" || line == "Y", nil
}
