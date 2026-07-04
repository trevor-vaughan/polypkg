package style

import (
	"bytes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ForWriter", func() {
	It("renders plain text for a non-TTY writer", func() {
		var buf bytes.Buffer
		s := ForWriter(&buf)
		Expect(s.Error.Render("error:")).To(Equal("error:"))
		Expect(s.Added.Render("+ hello")).To(Equal("+ hello"))
	})

	It("exposes all semantic styles", func() {
		var buf bytes.Buffer
		s := ForWriter(&buf)
		for _, r := range []string{
			s.Added.Render("a"), s.Removed.Render("a"), s.Changed.Render("a"),
			s.Header.Render("a"), s.Error.Render("a"), s.Hint.Render("a"),
			s.Emph.Render("a"),
		} {
			Expect(r).To(Equal("a"))
		}
	})
})
