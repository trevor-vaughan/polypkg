package cli

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// ttyInput is a stdin that claims to be a terminal, so an in-process test can
// answer a confirmation prompt.
type ttyInput struct{ io.Reader }

func (ttyInput) IsTerminal() bool { return true }

// zeroReader is an endless stream of NUL bytes with no newline, like /dev/zero.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestReadYes(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want bool
	}{
		{"y", "y\n", true},
		{"Y", "Y\n", true},
		{"y at EOF without a newline", "y", true},
		{"y padded with spaces", "  y  \n", true},
		{"n", "n\n", false},
		{"yes is not y", "yes\n", false},
		{"an empty line", "\n", false},
		{"EOF", "", false},
		{"y after the answer limit", strings.Repeat(" ", maxAnswerBytes) + "y\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readYes(strings.NewReader(tc.in))
			if err != nil {
				t.Fatalf("readYes(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("readYes(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestReadYesStopsOnAnEndlessAnswer(t *testing.T) {
	done := make(chan bool, 1)
	go func() {
		ok, _ := readYes(zeroReader{})
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("an endless stream of NUL bytes was read as yes")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readYes did not return on a stdin that never sends a newline")
	}
}

func TestIsInteractive(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = devNull.Close() })
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pipeR.Close(); _ = pipeW.Close() })

	for _, tc := range []struct {
		name string
		in   io.Reader
		want bool
	}{
		{"/dev/null is a character device but not a terminal", devNull, false},
		{"a pipe is not a terminal", pipeR, false},
		{"a plain reader is not a terminal", strings.NewReader("y\n"), false},
		{"a reader that reports a terminal", ttyInput{strings.NewReader("")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.SetIn(tc.in)
			if got := isInteractive(cmd); got != tc.want {
				t.Fatalf("isInteractive = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestInteractiveTTYNeedsAStdoutThatIsATerminal(t *testing.T) {
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = devNull.Close() })
	cmd := &cobra.Command{}
	cmd.SetIn(ttyInput{strings.NewReader("")})
	cmd.SetOut(devNull)
	if interactiveTTY(cmd) {
		t.Fatal("interactiveTTY = true with stdout on /dev/null; the picker would draw into nothing")
	}
}
