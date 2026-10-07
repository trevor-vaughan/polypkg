package planner_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/platform"
	"github.com/trevor-vaughan/polypkg/internal/repo"
)

var _ = Describe("Plan records each artifact's platform in the manifest", func() {
	It("writes the host platform for a per-platform artifact and nothing for an agnostic one", func() {
		r := newSignedRepo(GinkgoTB(), "repo")
		r.Publish(repo.BuildOptions{}, map[string]fixturePkg{
			"hello": {Version: "1.0.0", Platform: platform.Host()},
			"greet": {Version: "1.0.0"},
		})
		p := profileWithConstraints("repo", r.OutputDir, r.TrustRoot,
			map[string]string{"hello": ">=1.0.0", "greet": ">=1.0.0"})

		res, err := planner.Plan(GinkgoT().Context(), p, planner.Options{
			Scope:     "user",
			DataHome:  GinkgoT().TempDir(),
			StateHome: GinkgoT().TempDir(),
		})
		Expect(err).NotTo(HaveOccurred())

		got := map[string]string{}
		for _, e := range res.Manifest.Entries {
			got[e.Name] = e.Platform
		}
		Expect(got).To(Equal(map[string]string{
			"hello": platform.Host(),
			"greet": "",
		}))
	})
})
