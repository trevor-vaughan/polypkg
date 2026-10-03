package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// ansiEscape matches the SGR/cursor escape sequences huh/v2's TUI emits, so
// pty output can be matched on plain text.
var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;?=>]*[a-zA-Z]`)

var _ = Describe("search picker (real pty)", func() {
	// This is the only spec in the suite that drives the interactive picker
	// through a real terminal. It exists because nothing else does:
	// interactiveTTY (internal/cli/search.go) only shows the picker when both
	// stdin and stdout are *os.File values backed by character devices, and
	// every other search test wires bytes.Buffer I/O, so the picker branch
	// and everything behind it (runSearchPicker, runInstall) is unreachable
	// from an in-process test. That blind spot is exactly how the lock bug
	// shipped: emitSearchResult ran inside withCatalog's locked closure, so
	// every install started from the picker died on "another polypkg command
	// is already running", and no test noticed because no test could reach
	// the picker (fixed in b070689).
	//
	// script(1) (util-linux) allocates a real pty for the wrapped command, so
	// interactiveTTY sees character devices and shows the picker. This drives
	// a real binary (not the in-process cli.NewRootCmd() harness the rest of
	// this package uses) because the pty has to be the process's actual
	// stdin/stdout, not something attachable to an in-process cobra command.
	It("installs the ticked package through a real terminal", func() {
		if runtime.GOOS != "linux" {
			Skip("pty driver uses util-linux script(1); BSD script has no -c flag")
		}
		if _, err := exec.LookPath("script"); err != nil {
			Skip("script(1) not on PATH; it drives the huh picker through a real pty and " +
				"is required to exercise the only code path this test guards")
		}

		t := GinkgoTB()
		sandboxRoot := IsolatedEnv(t)
		// HOME is sandboxed defensively alongside the four XDG_* vars: nothing
		// in this path reads it today, but the subprocess must never be able
		// to fall back to the real user's home if that ever changes.
		t.Setenv("HOME", sandboxRoot)
		t.Setenv("POLYPKG_REPO_KEY_PASSWORD", "pw")

		workDir := t.TempDir()
		publicDir, trustRoot := buildLocalRepo(workDir)

		// polypkg init writes a profile with the source configured but no
		// packages pinned (its packages: block is commented out), so hello is
		// available to search and not yet installed -- the picker has to be
		// the thing that installs it.
		out, err := runCmd("init", "--source-url", publicDir, "--trust-root-file", trustRoot)
		Expect(err).NotTo(HaveOccurred(), "init: %s", out)

		cfgHome := os.Getenv("XDG_CONFIG_HOME")
		profilePath := filepath.Join(cfgHome, "polypkg", "profile.yaml")
		Expect(profilePath).To(BeAnExistingFile())
		t.Setenv("POLYPKG_PROFILE", profilePath)

		// Sanity check before trusting the pty run: confirm the in-process
		// harness (same env the subprocess below will inherit) actually finds
		// hello. If this fails, the pty assertions would fail for the wrong
		// reason -- no match, not the lock regression this test guards.
		searchOut, err := runCmd("search", "hello")
		Expect(err).NotTo(HaveOccurred(), "search: %s", searchOut)
		Expect(searchOut).To(ContainSubstring("hello"),
			"setup and the pty subprocess must agree on the sandbox; search found nothing")

		repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
		Expect(err).NotTo(HaveOccurred())
		Expect(filepath.Join(repoRoot, "go.mod")).To(BeAnExistingFile(),
			"expected ../.. from the test's working directory to be the module root")

		bin := filepath.Join(t.TempDir(), "polypkg")
		build := exec.Command("go", "build", "-o", bin, "./cmd/polypkg")
		build.Dir = repoRoot
		build.Env = append(os.Environ(), "GOTOOLCHAIN=auto")
		buildOut, err := build.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), "go build ./cmd/polypkg: %s", buildOut)

		// Space toggles the (only) match in the multi-select, Enter confirms.
		// The pipeline feeds those keystrokes into the pty script(1)
		// allocates for the wrapped command.
		pickerCmd := fmt.Sprintf("%s search hello", bin)
		shellPipeline := fmt.Sprintf(
			`( printf ' '; sleep 1.5; printf '\r'; sleep 5 ) | script -qec '%s' /dev/null`,
			pickerCmd)

		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		runner := exec.CommandContext(ctx, "sh", "-c", shellPipeline)
		// The chain is sh -> subshell/script -> the polypkg binary in its pty;
		// env only reaches the binary if it is set here, since script runs the
		// command through a shell of its own.
		runner.Env = os.Environ()

		var ptyOut bytes.Buffer
		runner.Stdout = &ptyOut
		runner.Stderr = &ptyOut
		runErr := runner.Run()
		Expect(ctx.Err()).NotTo(Equal(context.DeadlineExceeded),
			"pty run timed out (45s): %s", ptyOut.String())

		clean := ansiEscape.ReplaceAllString(ptyOut.String(), "")
		Expect(clean).NotTo(ContainSubstring("another polypkg command is already running"),
			"picker install hit the apply lock search itself still held: %s", clean)
		Expect(clean).To(ContainSubstring("applied generation 1"),
			"picker install did not reach completion: %s", clean)
		Expect(runErr).NotTo(HaveOccurred(), "script exited non-zero: %s", clean)

		// State is harder to fake than a log line: confirm the generation
		// store the picker's install wrote actually shows hello, using the
		// in-process harness under the same env the subprocess used.
		listOut, err := runCmd("list")
		Expect(err).NotTo(HaveOccurred(), "list: %s", listOut)
		Expect(listOut).To(ContainSubstring("hello"),
			"generation store does not show hello installed after the picker run")
	})
})
