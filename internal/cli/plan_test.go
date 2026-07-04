package cli

import (
	"bytes"
	"encoding/json"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/diff"
	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// diffWithAdded returns a diff.Result with one added package so that
// renderPlanText does not hit the "no changes pending" early return.
func diffWithAdded() diff.Result {
	return diff.Result{
		Packages: diff.PackageDiff{
			Added: []schema.ManifestEntry{
				{Name: "hello", Version: "1.0.0"},
			},
		},
	}
}

var _ = Describe("renderPlanText", func() {
	It("reports skipped recommended packages when present", func() {
		skipped := []resolver.SkippedRecommend{
			{
				Name:          "optional-lib",
				VersionRange:  ">=1.0.0",
				Reason:        "no candidate (unknown package)",
				RecommendedBy: []string{"hello"},
			},
		}
		var buf bytes.Buffer
		renderPlanText(&buf, "test.yaml", 0, diffWithAdded(), nil, skipped, nil)
		out := buf.String()

		Expect(out).To(ContainSubstring("skipped recommended"),
			"plan text should contain a skipped-recommended section")
		Expect(out).To(ContainSubstring("optional-lib"),
			"plan text should name the skipped package")
		Expect(out).To(ContainSubstring("no candidate (unknown package)"),
			"plan text should include the skip reason")
		Expect(out).To(ContainSubstring("hello"),
			"plan text should name the recommending package")
	})

	It("reports suggested packages when present", func() {
		suggests := []resolver.Suggestion{
			{
				Name:        "nice-to-have",
				SuggestedBy: "hello",
			},
		}
		var buf bytes.Buffer
		renderPlanText(&buf, "test.yaml", 0, diffWithAdded(), nil, nil, suggests)
		out := buf.String()

		Expect(out).To(ContainSubstring("suggested (not installed)"),
			"plan text should contain a suggests section")
		Expect(out).To(ContainSubstring("nice-to-have"),
			"plan text should name the suggested package")
		Expect(out).To(ContainSubstring("hello"),
			"plan text should name the suggesting package")
	})

	It("shows skipped recommends even when there are no package/ownership changes", func() {
		// NoChanges=true with no drift — the early-return path. Skipped should
		// still appear since the user explicitly asked for recommends.
		skipped := []resolver.SkippedRecommend{
			{Name: "lost-pkg", Reason: "conflict: foo=1.0"},
		}
		noChanges := diff.Result{NoChanges: true}
		var buf bytes.Buffer
		renderPlanText(&buf, "test.yaml", 1, noChanges, nil, skipped, nil)
		out := buf.String()

		Expect(out).To(ContainSubstring("skipped recommended"),
			"skipped recommends must appear even on no-changes output")
		Expect(out).To(ContainSubstring("lost-pkg"))
	})

	It("omits skipped/suggests sections when both are empty", func() {
		var buf bytes.Buffer
		renderPlanText(&buf, "test.yaml", 1, diff.Result{NoChanges: true}, nil, nil, nil)
		out := buf.String()

		Expect(out).NotTo(ContainSubstring("skipped recommended"))
		Expect(out).NotTo(ContainSubstring("suggested (not installed)"))
		Expect(out).To(ContainSubstring("no changes pending"))
	})
})

var _ = Describe("PlanResult JSON skipped/suggests", func() {
	It("marshals and round-trips skipped_recommends and suggests", func() {
		pr := schema.PlanResult{
			Schema:  "polypkg.plan/v1",
			Profile: "test.yaml",
			SkippedRecommends: []schema.PlanSkippedRecommend{
				{
					Name:          "optional-lib",
					VersionRange:  ">=1.0.0",
					Reason:        "no candidate (unknown package)",
					RecommendedBy: []string{"hello"},
				},
			},
			Suggests: []schema.PlanSuggestion{
				{
					Name:        "nice-to-have",
					SuggestedBy: "hello",
				},
			},
			Exit: 0,
		}

		data, err := json.Marshal(&pr)
		Expect(err).NotTo(HaveOccurred())

		out := string(data)
		Expect(out).To(ContainSubstring(`"skipped_recommends"`))
		Expect(out).To(ContainSubstring(`"optional-lib"`))
		Expect(out).To(ContainSubstring(`"suggests"`))
		Expect(out).To(ContainSubstring(`"nice-to-have"`))

		// Round-trip through ParsePlanResult (which validates the schema).
		parsed, err := schema.ParsePlanResult(strings.NewReader(out))
		Expect(err).NotTo(HaveOccurred())
		Expect(parsed.SkippedRecommends).To(HaveLen(1))
		Expect(parsed.SkippedRecommends[0].Name).To(Equal("optional-lib"))
		Expect(parsed.SkippedRecommends[0].Reason).To(Equal("no candidate (unknown package)"))
		Expect(parsed.Suggests).To(HaveLen(1))
		Expect(parsed.Suggests[0].Name).To(Equal("nice-to-have"))
		Expect(parsed.Suggests[0].SuggestedBy).To(Equal("hello"))
	})
})
