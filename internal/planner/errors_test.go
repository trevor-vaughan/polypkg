package planner

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("TrustRootError", func() {
	It("names the trust_root path and unwraps the cause", func() {
		cause := errors.New("anchor is not a valid minisign public key")
		e := &TrustRootError{Path: "/tmp/badkey.pub", Err: cause}
		Expect(e.Error()).To(ContainSubstring("/tmp/badkey.pub"))
		Expect(e.Error()).To(ContainSubstring("not a valid minisign public key"))
		Expect(errors.Is(e, cause)).To(BeTrue())
	})

	It("is extractable from a wrapped chain", func() {
		inner := &TrustRootError{Path: "/p", Err: errors.New("x")}
		var te *TrustRootError
		Expect(errors.As(error(inner), &te)).To(BeTrue())
		Expect(te.Path).To(Equal("/p"))
	})
})

var _ = Describe("ArtifactSignatureError", func() {
	It("names the artifact and source without leaking the verify detail", func() {
		cause := errors.New("verify signature: Invalid signature")
		e := &ArtifactSignatureError{Name: "hello", Version: "1.1.0", Source: "native", Err: cause}
		Expect(e.Error()).To(ContainSubstring("hello-1.1.0"))
		Expect(e.Error()).To(ContainSubstring(`from source "native"`))
		// The library failure-mode detail must not appear in the message.
		Expect(e.Error()).NotTo(ContainSubstring("Invalid signature"))
		Expect(e.Error()).NotTo(ContainSubstring("verify signature"))
		// But it stays in the chain for logs.
		Expect(errors.Is(e, cause)).To(BeTrue())
	})
})
