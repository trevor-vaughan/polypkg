package trust

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("NewVerifier anchor validation", func() {
	It("rejects an anchor that is not a valid minisign public key with a typed AnchorError", func() {
		// A non-key file (e.g. trust_root pointed at the wrong path).
		_, err := NewVerifier("polypkg-native", "this is not a minisign public key\n", "native")
		Expect(err).To(HaveOccurred())
		var ae *AnchorError
		Expect(errors.As(err, &ae)).To(BeTrue(), "expected *AnchorError, got %T: %v", err, err)
		// The library's "Invalid encoded public key" detail stays in the chain
		// for logs but the typed error's own message is clean.
		Expect(ae.Error()).To(ContainSubstring("not a valid minisign public key"))
	})

	It("accepts a well-formed anchor key", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(v).NotTo(BeNil())
	})

	It("still rejects an unknown source type before validating the anchor", func() {
		_, err := NewVerifier("bogus-type", "irrelevant", "native")
		Expect(err).To(HaveOccurred())
		var ae *AnchorError
		Expect(errors.As(err, &ae)).To(BeFalse())
	})
})
