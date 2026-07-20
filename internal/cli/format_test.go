package cli

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

var _ = Describe("ParseFormat", func() {
	DescribeTable("accepted values",
		func(in string, want Format, ok bool) {
			got, err := ParseFormat(in)
			if ok {
				Expect(err).NotTo(HaveOccurred())
				Expect(got).To(Equal(want))
			} else {
				Expect(err).To(HaveOccurred())
			}
		},
		Entry("text", "text", FormatText, true),
		Entry("json", "json", FormatJSON, true),
		Entry("empty defaults to text", "", FormatText, true),
		Entry("yaml rejected", "yaml", FormatText, false),
		Entry("unknown rejected", "xml", FormatText, false),
	)
})

var _ = Describe("EmitResult", func() {
	It("writes the text rendering in text mode", func() {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		EmitResult(cmd, FormatText, "apply", map[string]any{"gen_id": 7},
			func(w *bytes.Buffer, d map[string]any) {
				w.WriteString("applied generation 7\n")
			})
		Expect(out.String()).To(Equal("applied generation 7\n"))
	})

	It("writes a polypkg.cli-result/v2 envelope in json mode", func() {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		EmitResult(cmd, FormatJSON, "apply", map[string]any{"gen_id": 7}, nil)
		r, err := schema.ParseCLIResult(strings.NewReader(out.String()))
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Schema).To(Equal("polypkg.cli-result/v2"))
		Expect(r.Command).To(Equal("apply"))
		Expect(r.Status).To(Equal("ok"))
		Expect(r.Data["gen_id"]).To(BeEquivalentTo(7))
	})

	It("no-ops in text mode when textRenderer is nil", func() {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		EmitResult(cmd, FormatText, "apply", map[string]any{"gen_id": 7}, nil)
		Expect(out.String()).To(BeEmpty())
	})
})

var _ = Describe("WrapError", func() {
	It("returns nil for nil input", func() {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		Expect(WrapError(cmd, FormatJSON, "apply", nil)).To(BeNil())
		Expect(out.String()).To(BeEmpty())
	})

	It("returns the error unchanged in text mode", func() {
		cmd := &cobra.Command{}
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		err := WrapError(cmd, FormatText, "apply", errors.New("boom"))
		Expect(err).To(MatchError("boom"))
		Expect(out.String()).To(BeEmpty())
	})

	It("writes a status=error envelope in json mode and returns the error", func() {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		err := WrapError(cmd, FormatJSON, "apply", errors.New("boom"))
		Expect(err).To(MatchError("boom"))
		r, perr := schema.ParseCLIResult(strings.NewReader(out.String()))
		Expect(perr).NotTo(HaveOccurred())
		Expect(r.Status).To(Equal("error"))
		Expect(r.Error).To(Equal("boom"))
		Expect(r.Hint).To(BeEmpty())
	})
})

var _ = Describe("WrapError hint propagation", func() {
	It("emits schema v2 with a hint for CLIError", func() {
		cmd := NewRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		err := WrapError(cmd, FormatJSON, "rollback",
			&CLIError{Msg: "nothing to roll back", Hint: "run `polypkg apply` first"})
		Expect(err).To(HaveOccurred())
		Expect(out.String()).To(ContainSubstring(`"schema":"polypkg.cli-result/v2"`))
		Expect(out.String()).To(ContainSubstring(`"error":"nothing to roll back"`))
		Expect(out.String()).To(ContainSubstring(`"hint":"run ` + "`polypkg apply`" + ` first"`))
	})

	It("strips wrapper context, surfacing only the CLIError's Msg", func() {
		cmd := NewRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		_ = WrapError(cmd, FormatJSON, "apply",
			fmt.Errorf("open profile: %w", &CLIError{Msg: "bad file", Hint: "pass a path"}))
		Expect(out.String()).To(ContainSubstring(`"error":"bad file"`))
		Expect(out.String()).NotTo(ContainSubstring("open profile"))
	})
})

var _ = Describe("withRecoveryHint error chain", func() {
	It("errors.As(*trust.SourceNameMismatchError) survives WrapError wrapping", func() {
		inner := &trust.SourceNameMismatchError{Doc: "mypkg", Expected: "other"}
		wrapped := fmt.Errorf("source %q: %w", "other", inner)

		cmd := NewRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		returned := WrapError(cmd, FormatText, "apply", wrapped)

		var mm *trust.SourceNameMismatchError
		Expect(errors.As(returned, &mm)).To(BeTrue(),
			"errors.As(*SourceNameMismatchError) must find the original error through the CLIError wrapper")
		Expect(mm.Doc).To(Equal("mypkg"))
	})
})

var _ = Describe("resolveFormat", func() {
	It("returns FormatText when --format flag is absent", func() {
		cmd := &cobra.Command{}
		f, err := resolveFormat(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(f).To(Equal(FormatText))
	})

	It("parses the --format flag when present", func() {
		cmd := &cobra.Command{}
		cmd.Flags().String("format", "json", "")
		f, err := resolveFormat(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(f).To(Equal(FormatJSON))
	})

	It("propagates an invalid --format error", func() {
		cmd := &cobra.Command{}
		cmd.Flags().String("format", "yaml", "")
		_, err := resolveFormat(cmd)
		Expect(err).To(HaveOccurred())
	})
})
