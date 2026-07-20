package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/starlarkeval"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// commitFailSubstrate wraps a real substrate but always fails CommitGeneration,
// so a test can exercise the runner's behavior when the swap does not land after
// the pre-swap alternatives reconcile has already mutated the shared AltRoot.
type commitFailSubstrate struct {
	substrate.Substrate
}

func (commitFailSubstrate) CommitGeneration(string, *schema.Manifest, *schema.Ownership, map[string][]byte) (int, error) {
	return 0, errors.New("simulated commit failure")
}

var _ = Describe("Run alternatives rollback on commit failure", func() {
	It("restores the prior alternatives middle link when the commit fails", func() {
		dir := GinkgoT().TempDir()
		sub, err := substrate.NewOwnStore(filepath.Join(dir, "store"))
		Expect(err).NotTo(HaveOccurred())

		mkAlt := func(name string, priority int, source string) *schema.Package {
			return &schema.Package{
				Schema: "polypkg.package/v1", Name: name, Version: "1.0.0",
				Actions: []schema.PackageAction{{
					Phase: "post-place", Action: "alternatives",
					Params: map[string]any{"name": "editor", "source": source, "priority": priority},
				}},
			}
		}
		opts := func(s substrate.Substrate) Options {
			return Options{
				Substrate: s, Scope: "user", LockPath: filepath.Join(dir, "apply.lock"),
				StarlarkLimits: starlarkeval.Limits{MaxSteps: 1_000_000, Timeout: time.Second, MaxMemoryBytes: 64 << 20, MaxOutputBytes: 64 << 10},
			}
		}
		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
		mid := filepath.Join(sub.AltRoot(), "editor")

		// First apply commits: editor -> vim.
		_, err = New(opts(sub)).Run(context.Background(), m, []RunEntry{{Package: mkAlt("vim", 10, "$ACTIVE/vim/bin/vim")}})
		Expect(err).NotTo(HaveOccurred())
		target, rerr := os.Readlink(mid)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(target).To(ContainSubstring(filepath.Join("vim", "bin", "vim")))

		// Second apply repoints editor -> emacs but its commit fails. The pre-swap
		// reconcile already rewrote the stable middle link to emacs; because the
		// swap never landed, the runner must restore it to the prior winner (vim)
		// so the stable area matches the still-active generation.
		failing := commitFailSubstrate{Substrate: sub}
		_, err = New(opts(failing)).Run(context.Background(), m, []RunEntry{{Package: mkAlt("emacs", 30, "$ACTIVE/emacs/bin/emacs")}})
		Expect(err).To(HaveOccurred())

		target, rerr = os.Readlink(mid)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(target).To(ContainSubstring(filepath.Join("vim", "bin", "vim")),
			"middle link must be restored to the prior winner after a failed commit")
	})
})
