package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/cli"
)

// runComplete drives cobra's hidden __complete command under the current
// isolated env and returns the combined stdout+stderr output. Mirrors
// runAlternativesCmd but dispatches to __complete instead.
func runComplete(args ...string) string {
	GinkgoHelper()
	root := cli.NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"__complete"}, args...))
	Expect(root.Execute()).To(Succeed(), "__complete %v: %s", args, out.String())
	return out.String()
}

var _ = Describe("__complete dynamic completion e2e", func() {
	// All steps run inside one It so they share the same testing.TB and
	// therefore the same IsolatedEnv (t.Setenv is scoped to the T that
	// called it). The completion functions read XDG_DATA_HOME, which
	// IsolatedEnv sets, so runComplete sees the committed generation
	// produced by the real apply in the same It.
	It("returns live candidates derived from the committed generation", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		// --- step 1: build two alternatives providers of "editor" and apply ---
		// neovim: priority 30 (auto-winner); vim: priority 10 (auto-loser).
		pkgNeovim := pkgProvidingAlt(t, "neovim", "nvim", "editor", 30)
		pkgVim := pkgProvidingAlt(t, "vim", "vim", "editor", 10)

		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "neovim", version: "1.0.0", artifact: pkgNeovim},
			indexPkg{name: "vim", version: "1.0.0", artifact: pkgVim},
		)
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		out, err := applyProfileWith(t, srv.URL, trust, "neovim", "vim")
		Expect(err).NotTo(HaveOccurred(), "apply output: %s", out)

		// --- step 2: alternatives set <TAB> offers the alternative name ---
		// Without ValidArgsFunction wired on the `set` positional arg 0, cobra
		// falls back to file completion and would NOT emit "editor".
		out2 := runComplete("alternatives", "set", "")
		Expect(out2).To(ContainSubstring("editor"))

		// --- step 3: alternatives set editor <TAB> offers both providers ---
		// Without ValidArgsFunction dispatching to completeAltProviders for
		// positional arg 1, cobra would fall back to file completion and would
		// NOT emit the provider package names.
		out3 := runComplete("alternatives", "set", "editor", "")
		Expect(out3).To(ContainSubstring("neovim"))
		Expect(out3).To(ContainSubstring("vim"))

		// --- step 4: rollback --to <TAB> offers the committed generation ID ---
		// The apply above committed generation 1; completeGenerations reads
		// sub.ListGenerations() which scans <XDG_DATA_HOME>/polypkg/generations/.
		// Without RegisterFlagCompletionFunc("to", completeGenerations) wired,
		// cobra would emit no candidates and the assertion would fail.
		out4 := runComplete("rollback", "--to", "")
		Expect(out4).To(ContainSubstring("1"))
	})
})
