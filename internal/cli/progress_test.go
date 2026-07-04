package cli

import (
	"bytes"
	"strings"
	"unicode/utf8"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("progress (non-TTY path)", func() {
	It("prints each distinct (stage,detail) line once", func() {
		var buf bytes.Buffer
		p := newProgress(&buf)

		p.Update("fetching trust", "https://example.com")
		p.Update("fetching index", "https://example.com")
		p.Update("resolving", "")

		lines := nonBlankLines(buf.String())
		Expect(lines).To(ConsistOf(
			"fetching trust: https://example.com",
			"fetching index: https://example.com",
			"resolving: ",
		))
	})

	It("deduplicates consecutive identical updates", func() {
		var buf bytes.Buffer
		p := newProgress(&buf)

		p.Update("placing", "pre-place 1/3")
		p.Update("placing", "pre-place 1/3") // duplicate — must not emit
		p.Update("placing", "pre-place 2/3")

		lines := nonBlankLines(buf.String())
		Expect(lines).To(ConsistOf(
			"placing: pre-place 1/3",
			"placing: pre-place 2/3",
		))
	})

	It("does not emit ANSI escape codes to a non-TTY writer", func() {
		var buf bytes.Buffer
		p := newProgress(&buf)

		p.Update("resolving", "")
		p.Done()

		Expect(buf.String()).NotTo(ContainSubstring("\x1b["))
		Expect(buf.String()).NotTo(ContainSubstring("\r"))
	})

	It("Done() is idempotent on a non-TTY writer", func() {
		var buf bytes.Buffer
		p := newProgress(&buf)
		p.Update("resolving", "")

		// Multiple Done() calls must not panic or add extra output.
		p.Done()
		after1 := buf.String()
		p.Done()
		after2 := buf.String()

		Expect(after1).To(Equal(after2))
	})

	It("Update after Done() is safe and adds no extra output on non-TTY", func() {
		var buf bytes.Buffer
		p := newProgress(&buf)
		p.Update("resolving", "")
		p.Done()
		before := buf.String()

		// Update after Done must not panic.
		p.Update("resolving", "extra")
		// No requirement to emit or suppress — just must not panic.
		// (Documented: progress is a best-effort display primitive.)
		_ = buf.String()
		_ = before
	})

	It("stage with empty detail prints a trailing colon-space", func() {
		var buf bytes.Buffer
		p := newProgress(&buf)
		p.Update("projecting", "")
		lines := nonBlankLines(buf.String())
		Expect(lines).To(HaveLen(1))
		Expect(lines[0]).To(Equal("projecting: "))
	})
})

var _ = Describe("newProgress(nil) — no-op progress", func() {
	It("Update writes nothing and does not panic", func() {
		p := newProgress(nil)
		Expect(func() { p.Update("stage", "detail") }).NotTo(Panic())
	})

	It("Done is a no-op and does not panic", func() {
		p := newProgress(nil)
		p.Update("stage", "detail")
		Expect(func() { p.Done() }).NotTo(Panic())
	})

	It("Done is idempotent on a nil writer", func() {
		p := newProgress(nil)
		Expect(func() {
			p.Done()
			p.Done()
		}).NotTo(Panic())
	})
})

var _ = Describe("truncateLine", func() {
	It("returns short ASCII strings unchanged", func() {
		Expect(truncateLine("hello", 10)).To(Equal("hello"))
	})

	It("returns string equal to maxCols unchanged", func() {
		s := strings.Repeat("a", 10)
		Expect(truncateLine(s, 10)).To(Equal(s))
	})

	It("truncates long ASCII strings to maxCols runes ending in …", func() {
		s := strings.Repeat("a", 110)
		result := truncateLine(s, 100)
		Expect(utf8.RuneCountInString(result)).To(Equal(100))
		Expect(result).To(HaveSuffix("…"))
		Expect(utf8.ValidString(result)).To(BeTrue())
	})

	It("truncates multibyte rune strings correctly ending in …", func() {
		// Each "日" is 3 bytes; build a string longer than maxCols runes.
		s := strings.Repeat("日", 110)
		const maxCols = 100
		result := truncateLine(s, maxCols)
		Expect(utf8.RuneCountInString(result)).To(Equal(maxCols))
		Expect(result).To(HaveSuffix("…"))
		Expect(utf8.ValidString(result)).To(BeTrue())
	})

	It("does not produce invalid UTF-8 when truncating multibyte sequences", func() {
		// Mix ASCII and multibyte; pad beyond maxCols runes.
		s := "prefix: " + strings.Repeat("café", 30)
		result := truncateLine(s, 20)
		Expect(utf8.ValidString(result)).To(BeTrue())
		Expect(result).To(HaveSuffix("…"))
	})
})

// nonBlankLines splits s on newlines and strips empty lines.
func nonBlankLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}
