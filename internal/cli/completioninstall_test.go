package cli

import (
	"bytes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/linkfarm"
)

var _ = Describe("writeCompletionSummary", func() {
	It("reports linked completions per shell and emits the zsh fpath nudge", func() {
		var w bytes.Buffer
		res := map[string]linkfarm.Result{
			"bash": {Linked: []string{"rg"}},
			"zsh":  {Linked: []string{"_rg"}},
		}
		writeCompletionSummary(&w, res, map[string]string{
			"bash": "/d/bash-completion/completions",
			"zsh":  "/d/zsh/site-functions",
		})
		out := w.String()
		Expect(out).To(ContainSubstring("completion"))
		Expect(out).To(ContainSubstring("fpath"))
		Expect(out).To(ContainSubstring("/d/zsh/site-functions"))
	})

	It("emits no nudge when no zsh completions were linked", func() {
		var w bytes.Buffer
		res := map[string]linkfarm.Result{"bash": {Linked: []string{"rg"}}}
		writeCompletionSummary(&w, res, map[string]string{"bash": "/d/bash-completion/completions"})
		Expect(w.String()).NotTo(ContainSubstring("fpath"))
	})
})
