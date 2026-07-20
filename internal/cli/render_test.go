package cli

import (
	"bytes"
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RenderError", func() {
	It("prints error and hint lines for a CLIError", func() {
		var buf bytes.Buffer
		RenderError(&buf, &CLIError{Msg: "no profile found", Hint: "pass a profile path"})
		Expect(buf.String()).To(Equal("error: no profile found\nhint: pass a profile path\n"))
	})

	It("prints only the error line when there is no hint", func() {
		var buf bytes.Buffer
		RenderError(&buf, errors.New("plain failure"))
		Expect(buf.String()).To(Equal("error: plain failure\n"))
	})

	It("finds a CLIError inside a wrapped chain", func() {
		var buf bytes.Buffer
		RenderError(&buf, fmt.Errorf("ctx: %w", &CLIError{Msg: "inner", Hint: "h"}))
		Expect(buf.String()).To(Equal("error: inner\nhint: h\n"))
	})

	It("prints nothing for a quiet StatusError", func() {
		var buf bytes.Buffer
		RenderError(&buf, &StatusError{Code: 2, Quiet: true, Msg: "changes pending"})
		Expect(buf.String()).To(BeEmpty())
	})

	It("prints nothing for a quiet StatusError inside a wrapped chain", func() {
		var buf bytes.Buffer
		RenderError(&buf, fmt.Errorf("w: %w", &StatusError{Code: 2, Quiet: true, Msg: "changes pending"}))
		Expect(buf.String()).To(BeEmpty())
	})
})

var _ = Describe("ExitCode", func() {
	It("returns 0 for nil, 1 for plain errors, the carried code for StatusError", func() {
		Expect(ExitCode(nil)).To(Equal(0))
		Expect(ExitCode(errors.New("x"))).To(Equal(1))
		Expect(ExitCode(&StatusError{Code: 2})).To(Equal(2))
		Expect(ExitCode(fmt.Errorf("w: %w", &StatusError{Code: 2}))).To(Equal(2))
	})
})
