package planner_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// copyFileT copies one published metadata file aside so a spec can serve an
// older (still-signed) copy after a republish.
func copyFileT(tb testing.TB, src, dst string) {
	tb.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		tb.Fatal(err)
	}
}

var _ = Describe("Plan metadata freshness (D13)", func() {
	var restore func()
	AfterEach(func() {
		if restore != nil {
			restore()
			restore = nil
		}
	})

	planOpts := func(stateHome string) planner.Options {
		return planner.Options{Scope: "user", DataHome: GinkgoT().TempDir(), StateHome: stateHome}
	}

	It("refuses a trust document past its expires without advancing stored serials", func() {
		out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{ValidFor: time.Hour})
		p := profileForLocalSource("repo", out, tr)
		stateHome := GinkgoT().TempDir()

		// Advance the consumer clock past expires (now+1h) plus the 5m skew.
		restore = trust.SetTimeNowForTesting(func() time.Time {
			return time.Now().Add(time.Hour + 6*time.Minute)
		})
		_, err := planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).To(MatchError(ContainSubstring("trust document expired at")))
		Expect(err).To(MatchError(ContainSubstring("stale metadata refused")))

		// The freeze rejection must not have advanced any high-water mark.
		seen, serr := trust.LoadSeen(stateHome, "repo")
		Expect(serr).NotTo(HaveOccurred())
		Expect(seen).To(Equal(trust.Seen{}))
	})

	It("accepts metadata past expires but within the clock-skew tolerance", func() {
		out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{ValidFor: time.Hour})
		p := profileForLocalSource("repo", out, tr)

		// Derive the injected clock from the PUBLISHED expires (the index and
		// trust document share the stamp) rather than time.Now(), so real
		// minutes elapsing between build and Plan cannot flip the spec. 5m is
		// trust's expirySkew; one second inside it must still be accepted.
		expires, perr := time.Parse(time.RFC3339, readPublishedIndex(GinkgoTB(), out).Expires)
		Expect(perr).NotTo(HaveOccurred())
		restore = trust.SetTimeNowForTesting(func() time.Time {
			return expires.Add(5*time.Minute - time.Second)
		})
		res, err := planner.Plan(GinkgoT().Context(), p, planOpts(GinkgoT().TempDir()))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Manifest.Entries).To(HaveLen(1))
	})

	It("refuses an expired index even under a fresh trust document, without advancing stored serials", func() {
		r := newSignedRepo(GinkgoTB(), "repo")
		// First publish with the default 720h window; stash its long-lived
		// trust document.
		r.Publish(repo.BuildOptions{}, map[string]fixturePkg{"hello": {Version: "1.0.0"}})
		side := GinkgoT().TempDir()
		copyFileT(GinkgoTB(), filepath.Join(r.OutputDir, "trust.json"), filepath.Join(side, "trust.json"))
		copyFileT(GinkgoTB(), filepath.Join(r.OutputDir, "trust.json.minisig"), filepath.Join(side, "trust.json.minisig"))

		// Republish with changed content and a 1h window: the index restamps
		// expires = now+1h while the stashed trust doc stays valid for 720h.
		r.Publish(repo.BuildOptions{ValidFor: time.Hour}, map[string]fixturePkg{"hello": {Version: "1.0.1"}})

		p := profileWithConstraints("repo", r.OutputDir, r.TrustRoot, map[string]string{"hello": ">=1.0.0"})
		src := p.Sources.Sources["repo"]
		src.TrustDoc = filepath.Join(side, "trust.json")
		p.Sources.Sources["repo"] = src

		stateHome := GinkgoT().TempDir()
		restore = trust.SetTimeNowForTesting(func() time.Time {
			return time.Now().Add(time.Hour + 6*time.Minute)
		})
		_, err := planner.Plan(GinkgoT().Context(), p, planOpts(stateHome))
		Expect(err).To(MatchError(ContainSubstring("index expired at")))
		Expect(err).To(MatchError(ContainSubstring("stale metadata refused")))

		// The stale index must not have advanced serials or package HWMs.
		seen, serr := trust.LoadSeen(stateHome, "repo")
		Expect(serr).NotTo(HaveOccurred())
		Expect(seen).To(Equal(trust.Seen{}))
	})

	It("surfaces freshness grace on the Plan Result for a graced source", func() {
		out, tr := buildSignedLocalRepo(GinkgoTB(), "repo", repo.BuildOptions{})
		p := profileForLocalSource("repo", out, tr)
		p.Sources.Sources["repo"] = withAcceptExpiryUntil(p.Sources.Sources["repo"], "2999-01-01T00:00:00Z")
		restore = trust.SetTimeNowForTesting(func() time.Time {
			return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
		})
		res, err := planner.Plan(GinkgoT().Context(), p, planOpts(GinkgoT().TempDir()))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.FreshnessGraced).To(ContainElement(And(
			HaveField("Source", Equal("repo")),
			HaveField("What", Equal("index")),
			HaveField("AcceptUntil", Equal("2999-01-01T00:00:00Z")),
		)))
	})
})
