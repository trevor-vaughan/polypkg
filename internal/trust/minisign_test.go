package trust

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// wrongPubKey is a well-formed minisign public key from a DIFFERENT keypair
// than the one that signed the testdata fixtures. Verifying the fixture
// signature against it must fail on a key-identifier mismatch, exercising the
// cryptographic verification path (not merely parsing). A public key is not a
// secret, so embedding it here is safe.
const wrongPubKey = `untrusted comment: minisign public key (non-matching)
RWTVLZ1iogs6EB4pagAbTrznfbv0WeMqZf027uwha81Vp6owOTr2MIhl
`

var _ = Describe("Verify", func() {
	var (
		pubKey []byte
		msg    []byte
		sig    []byte
	)

	BeforeEach(func() {
		dir := "testdata"
		var err error
		pubKey, err = os.ReadFile(filepath.Join(dir, "test.pub"))
		Expect(err).NotTo(HaveOccurred())
		msg, err = os.ReadFile(filepath.Join(dir, "msg.txt"))
		Expect(err).NotTo(HaveOccurred())
		sig, err = os.ReadFile(filepath.Join(dir, "msg.txt.minisig"))
		Expect(err).NotTo(HaveOccurred())
	})

	It("accepts a valid signature", func() {
		Expect(Verify(string(pubKey), msg, string(sig))).To(Succeed())
	})

	It("rejects a tampered message", func() {
		Expect(Verify(string(pubKey), []byte("modified"), string(sig))).NotTo(Succeed())
	})

	It("rejects a structurally malformed key", func() {
		// No "untrusted comment:" line: must be rejected at parse.
		malformedKey := "RWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		Expect(Verify(malformedKey, msg, string(sig))).NotTo(Succeed())
	})

	It("rejects a signature made by a different key", func() {
		Expect(Verify(wrongPubKey, msg, string(sig))).NotTo(Succeed())
	})
})

var _ = Describe("verifyMinisign", func() {
	It("returns the trusted comment (prefix stripped) and a key ID matching sigKeyID", func() {
		dir := "testdata"
		pubKey, err := os.ReadFile(filepath.Join(dir, "test.pub"))
		Expect(err).NotTo(HaveOccurred())
		msg, err := os.ReadFile(filepath.Join(dir, "msg.txt"))
		Expect(err).NotTo(HaveOccurred())
		sig, err := os.ReadFile(filepath.Join(dir, "msg.txt.minisig"))
		Expect(err).NotTo(HaveOccurred())

		comment, keyID, err := verifyMinisign(string(pubKey), msg, string(sig))
		Expect(err).NotTo(HaveOccurred())
		Expect(comment).NotTo(ContainSubstring("trusted comment:"))

		id2, err := sigKeyID(string(sig))
		Expect(err).NotTo(HaveOccurred())
		Expect(keyID).To(Equal(id2))
	})
})
