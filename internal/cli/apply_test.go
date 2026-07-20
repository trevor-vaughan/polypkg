package cli

import (
	"bytes"
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/cli/style"
	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/runner"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("validatePlacementPhases", func() {
	It("rejects file-placing actions in post-swap phases", func() {
		entries := []runner.RunEntry{{Package: &schema.Package{
			Name: "bad",
			Actions: []schema.PackageAction{
				{Phase: "post-activate", Action: "install", Params: map[string]any{"src": "a", "dest": "b"}},
			},
		}}}
		err := validatePlacementPhases(entries)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("post-swap"))
		Expect(err.Error()).To(ContainSubstring("install"))
	})

	It("allows file-placing actions in pre-swap phases", func() {
		entries := []runner.RunEntry{{Package: &schema.Package{
			Name: "ok",
			Actions: []schema.PackageAction{
				{Phase: "post-place", Action: "install", Params: map[string]any{}},
				{Phase: "pre-activate", Action: "perms", Params: map[string]any{}},
			},
		}}}
		Expect(validatePlacementPhases(entries)).NotTo(HaveOccurred())
	})
})

var _ = Describe("apply command", func() {
	It("registers heal-drift and no-drift-check flags defaulting to false", func() {
		cmd := newApplyCmd()
		for _, name := range []string{"heal-drift", "no-drift-check"} {
			f := cmd.Flag(name)
			Expect(f).NotTo(BeNil(), "flag %q must be registered", name)
			Expect(f.DefValue).To(Equal("false"), "flag %q must default to false", name)
		}
	})
})

var _ = Describe("renderWeakSummary", func() {
	It("renders skipped recommended packages", func() {
		skipped := []resolver.SkippedRecommend{
			{
				Name:          "optional-lib",
				VersionRange:  ">=1.0.0",
				Reason:        "no candidate (unknown package)",
				RecommendedBy: []string{"hello"},
			},
		}
		var buf bytes.Buffer
		st := style.ForWriter(&buf)
		renderWeakSummary(&buf, st, skipped, nil)
		out := buf.String()

		Expect(out).To(ContainSubstring("skipped recommended"),
			"weak summary must contain a skipped-recommended section")
		Expect(out).To(ContainSubstring("optional-lib"),
			"weak summary must name the skipped package")
		Expect(out).To(ContainSubstring("no candidate (unknown package)"),
			"weak summary must include the skip reason")
		Expect(out).To(ContainSubstring("hello"),
			"weak summary must name the recommending package")
	})

	It("renders suggested packages", func() {
		suggests := []resolver.Suggestion{
			{
				Name:        "nice-to-have",
				SuggestedBy: "hello",
			},
		}
		var buf bytes.Buffer
		st := style.ForWriter(&buf)
		renderWeakSummary(&buf, st, nil, suggests)
		out := buf.String()

		Expect(out).To(ContainSubstring("suggested (not installed)"),
			"weak summary must contain a suggests section")
		Expect(out).To(ContainSubstring("nice-to-have"),
			"weak summary must name the suggested package")
		Expect(out).To(ContainSubstring("hello"),
			"weak summary must name the suggesting package")
	})

	It("writes nothing when both slices are empty", func() {
		var buf bytes.Buffer
		st := style.ForWriter(&buf)
		renderWeakSummary(&buf, st, nil, nil)
		Expect(buf.String()).To(BeEmpty(), "renderWeakSummary must produce no output when both inputs are nil")
	})
})

var _ = Describe("applyOutcome weak summary", func() {
	It("includes skipped_recommends and suggests in the data map when non-empty", func() {
		out := &applyOutcome{
			gen: 1,
			skipped: []resolver.SkippedRecommend{
				{Name: "opt-lib", Reason: "no candidate", RecommendedBy: []string{"core"}},
			},
			suggests: []resolver.Suggestion{
				{Name: "nice-pkg", SuggestedBy: "core"},
			},
		}
		data := out.data()

		Expect(data).To(HaveKey("skipped_recommends"),
			"apply data must carry skipped_recommends when non-empty")
		Expect(data).To(HaveKey("suggests"),
			"apply data must carry suggests when non-empty")

		// Verify the toPlanSkipped transform preserves content through the data map.
		raw, merr := json.Marshal(data["skipped_recommends"])
		Expect(merr).NotTo(HaveOccurred())
		var skippedList []map[string]any
		Expect(json.Unmarshal(raw, &skippedList)).To(Succeed())
		Expect(skippedList).To(HaveLen(1))
		Expect(skippedList[0]["name"]).To(Equal("opt-lib"))
		Expect(skippedList[0]["reason"]).To(Equal("no candidate"))
		Expect(skippedList[0]["recommended_by"]).To(ConsistOf("core"))
	})

	It("omits skipped_recommends and suggests from the data map when empty", func() {
		out := &applyOutcome{gen: 1}
		data := out.data()

		Expect(data).NotTo(HaveKey("skipped_recommends"),
			"apply data must omit skipped_recommends when empty")
		Expect(data).NotTo(HaveKey("suggests"),
			"apply data must omit suggests when empty")
	})

	It("renders weak summary in text output when skipped is non-empty", func() {
		out := &applyOutcome{
			gen: 2,
			skipped: []resolver.SkippedRecommend{
				{Name: "opt-lib", Reason: "no candidate", RecommendedBy: []string{"core"}},
			},
		}
		var buf bytes.Buffer
		out.renderText(&buf, nil)
		text := buf.String()

		Expect(text).To(ContainSubstring("skipped recommended"),
			"apply text must contain a skipped-recommended section")
		Expect(text).To(ContainSubstring("opt-lib"),
			"apply text must name the skipped package")
	})
})
