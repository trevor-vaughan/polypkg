package cli

import (
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CLIError", func() {
	It("renders Msg as Error() and unwraps Err", func() {
		cause := errors.New("boom")
		e := &CLIError{Msg: "cannot open profile", Hint: "pass a path", Err: cause}
		Expect(e.Error()).To(Equal("cannot open profile"))
		Expect(errors.Is(e, cause)).To(BeTrue())
	})

	It("is extractable from a wrapped chain", func() {
		e := fmt.Errorf("outer: %w", &CLIError{Msg: "inner", Hint: "h"})
		var ce *CLIError
		Expect(errors.As(e, &ce)).To(BeTrue())
		Expect(ce.Hint).To(Equal("h"))
	})
})

var _ = Describe("StatusError", func() {
	It("carries an exit code and quiet flag", func() {
		e := &StatusError{Code: 2, Quiet: true, Msg: "changes pending"}
		Expect(e.Error()).To(Equal("changes pending"))
		Expect(e.ExitCode()).To(Equal(2))
	})

	It("is extractable from a wrapped chain", func() {
		e := fmt.Errorf("outer: %w", &StatusError{Code: 2, Msg: "pending"})
		var se *StatusError
		Expect(errors.As(e, &se)).To(BeTrue())
		Expect(se.Code).To(Equal(2))
	})
})
