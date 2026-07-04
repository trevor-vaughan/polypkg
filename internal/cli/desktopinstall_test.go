package cli

import (
	"bytes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/linkfarm"
)

var _ = Describe("writeDesktopSummary", func() {
	It("reports installed and removed desktop files", func() {
		var w bytes.Buffer
		writeDesktopSummary(&w, linkfarm.Result{Linked: []string{"org.foo.Bar.desktop"}, Pruned: []string{"old.desktop"}}, "/d/applications")
		out := w.String()
		Expect(out).To(ContainSubstring("installed 1 desktop file"))
		Expect(out).To(ContainSubstring("org.foo.Bar.desktop"))
		Expect(out).To(ContainSubstring("removed 1 desktop file"))
		Expect(out).To(ContainSubstring("old.desktop"))
	})

	It("prints nothing when there is no change", func() {
		var w bytes.Buffer
		writeDesktopSummary(&w, linkfarm.Result{}, "/d/applications")
		Expect(w.String()).To(BeEmpty())
	})

	It("reports skipped foreign desktop files", func() {
		var w bytes.Buffer
		writeDesktopSummary(&w, linkfarm.Result{Skipped: []linkfarm.Conflict{{Name: "org.foo.Bar.desktop", Existing: "file"}}}, "/d/applications")
		out := w.String()
		Expect(out).To(ContainSubstring("skipped 1 desktop file"))
		Expect(out).To(ContainSubstring("org.foo.Bar.desktop"))
	})
})
