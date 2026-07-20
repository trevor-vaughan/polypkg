package cli

import (
	"bytes"
	"errors"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"
)

var _ = Describe("formatVersionList", func() {
	It("returns single version verbatim", func() {
		Expect(formatVersionList([]string{"1.0.0"})).To(Equal("1.0.0"))
	})

	It("returns up to three versions joined by comma-space", func() {
		Expect(formatVersionList([]string{"1.2.0", "1.1.0", "1.0.0"})).
			To(Equal("1.2.0, 1.1.0, 1.0.0"))
	})

	It("caps at three and appends +N more for five versions", func() {
		versions := []string{"5.0.0", "4.0.0", "3.0.0", "2.0.0", "1.0.0"}
		result := formatVersionList(versions)
		Expect(result).To(Equal("5.0.0, 4.0.0, 3.0.0 (+2 more)"))
	})

	It("caps at three and appends +1 more for four versions", func() {
		versions := []string{"4.0.0", "3.0.0", "2.0.0", "1.0.0"}
		result := formatVersionList(versions)
		Expect(result).To(Equal("4.0.0, 3.0.0, 2.0.0 (+1 more)"))
	})

	It("returns empty string for empty slice", func() {
		Expect(formatVersionList(nil)).To(Equal(""))
	})
})

var _ = Describe("filterNames", func() {
	names := []string{"hello", "world", "help", "go-hello", "HELLO-world"}

	It("returns names containing the term (case-insensitive)", func() {
		result := filterNames(names, "hello")
		Expect(result).To(ConsistOf("hello", "go-hello", "HELLO-world"))
	})

	It("returns all names when term is empty string", func() {
		result := filterNames(names, "")
		Expect(result).To(ConsistOf(names))
	})

	It("returns empty slice when nothing matches", func() {
		result := filterNames(names, "zzz")
		Expect(result).To(BeEmpty())
	})

	It("is case-insensitive for uppercase term", func() {
		result := filterNames(names, "WORLD")
		Expect(result).To(ConsistOf("world", "HELLO-world"))
	})
})

var _ = Describe("search command argument validation", func() {
	setup := func() {
		dir := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", dir+"/data")
		GinkgoT().Setenv("XDG_STATE_HOME", dir+"/state")
	}

	It("returns CLIError when no search term is supplied", func() {
		setup()
		root := NewRootCmd()
		root.SetArgs([]string{"search"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(ContainSubstring("search"))
		Expect(cliErr.Msg).To(ContainSubstring("<term>"))
	})

	It("returns CLIError when more than one term is supplied", func() {
		setup()
		root := NewRootCmd()
		root.SetArgs([]string{"search", "foo", "bar"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
	})
})

var _ = Describe("searchNoMatchText", func() {
	It("produces the friendly no-match line for a given term", func() {
		var sb strings.Builder
		writeNoMatchLine(&sb, "zzz")
		Expect(sb.String()).To(Equal(`no packages matching "zzz"` + "\n"))
	})
})

var _ = Describe("interactiveTTY", func() {
	// interactiveTTY returns false whenever stdin or stdout is a bytes.Buffer
	// (not an *os.File), which is always the case in in-process tests.

	It("returns false when stdout is a buffer (non-TTY)", func() {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		// stdin is also a buffer (the cobra default when not set)
		Expect(interactiveTTY(cmd)).To(BeFalse())
	})

	It("returns false when stdin is a buffer (non-TTY)", func() {
		cmd := &cobra.Command{}
		var in bytes.Buffer
		var out bytes.Buffer
		cmd.SetIn(&in)
		cmd.SetOut(&out)
		Expect(interactiveTTY(cmd)).To(BeFalse())
	})
})

var _ = Describe("searchOptionLabel", func() {
	It("formats name with newest version in parens", func() {
		label := searchOptionLabel("hello", []string{"1.1.0", "1.0.0"})
		Expect(label).To(Equal("hello (1.1.0)"))
	})

	It("formats name with single version", func() {
		label := searchOptionLabel("world", []string{"2.0.0"})
		Expect(label).To(Equal("world (2.0.0)"))
	})

	It("formats name with no version as name only", func() {
		label := searchOptionLabel("nover", nil)
		Expect(label).To(Equal("nover"))
	})
})

var _ = Describe("search picker gate", func() {
	// Verify that emitSearchResult skips the picker when stdout is not a TTY
	// (i.e., in-process test environment). The plain table must still appear.

	It("emits the plain table when stdout is a buffer regardless of match count", func() {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)

		rows := []searchMatch{
			{Name: "hello", Versions: []string{"1.1.0", "1.0.0"}},
		}
		err := emitSearchResult(cmd, FormatText, "hello", rows)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).To(ContainSubstring("hello"))
		Expect(out.String()).To(ContainSubstring("1.1.0"))
	})

	It("emits no-match line and no picker when rows is empty", func() {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)

		err := emitSearchResult(cmd, FormatText, "zzz", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).To(ContainSubstring(`no packages matching "zzz"`))
	})
})
