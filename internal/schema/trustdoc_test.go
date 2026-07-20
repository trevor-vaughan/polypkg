package schema

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const validTrustDoc = `{
  "schema": "polypkg.trust/v2",
  "source": "native",
  "serial": 7,
  "issued_at": "2026-05-25T00:00:00Z",
  "expires": "2099-01-01T00:00:00Z",
  "keys": [
    { "id": "3a1f5c9e2b7d04a8", "pubkey": "RWQabc", "roles": ["index", "artifact"] }
  ],
  "revoked": ["00deadbeef00cafe"]
}`

var _ = Describe("ParseTrustDoc", func() {
	It("parses a valid trust document", func() {
		td, err := ParseTrustDoc(strings.NewReader(validTrustDoc))
		Expect(err).NotTo(HaveOccurred())
		Expect(td.Schema).To(Equal("polypkg.trust/v2"))
		Expect(td.Source).To(Equal("native"))
		Expect(td.Serial).To(Equal(uint64(7)))
		Expect(td.Expires).To(Equal("2099-01-01T00:00:00Z"))
		Expect(td.Keys).To(HaveLen(1))
		Expect(td.Keys[0].ID).To(Equal("3a1f5c9e2b7d04a8"))
		Expect(td.Keys[0].Roles).To(Equal([]string{"index", "artifact"}))
		Expect(td.Revoked).To(Equal([]string{"00deadbeef00cafe"}))
	})

	It("parses a key carrying the attestation role", func() {
		doc := `{"schema":"polypkg.trust/v2","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","keys":[{"id":"3a1f5c9e2b7d04a8","pubkey":"p","roles":["index","artifact","attestation"]}]}`
		td, err := ParseTrustDoc(strings.NewReader(doc))
		Expect(err).NotTo(HaveOccurred())
		Expect(td.Keys[0].Roles).To(Equal([]string{"index", "artifact", "attestation"}))
	})
})

var _ = DescribeTable("ParseTrustDoc rejects invalid documents",
	func(doc string) {
		_, err := ParseTrustDoc(strings.NewReader(doc))
		Expect(err).To(HaveOccurred())
	},
	Entry("wrong schema",
		`{"schema":"polypkg.trust/v1","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","keys":[{"id":"3a1f5c9e2b7d04a8","pubkey":"p","roles":["index"]}]}`),
	Entry("missing expires",
		`{"schema":"polypkg.trust/v2","source":"native","serial":1,"keys":[{"id":"3a1f5c9e2b7d04a8","pubkey":"p","roles":["index"]}]}`),
	Entry("empty keys",
		`{"schema":"polypkg.trust/v2","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","keys":[]}`),
	Entry("missing source",
		`{"schema":"polypkg.trust/v2","serial":1,"expires":"2099-01-01T00:00:00Z","keys":[{"id":"3a1f5c9e2b7d04a8","pubkey":"p","roles":["index"]}]}`),
	Entry("bad id pattern",
		`{"schema":"polypkg.trust/v2","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","keys":[{"id":"NOTHEX","pubkey":"p","roles":["index"]}]}`),
	Entry("bad role enum",
		`{"schema":"polypkg.trust/v2","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","keys":[{"id":"3a1f5c9e2b7d04a8","pubkey":"p","roles":["root"]}]}`),
	Entry("empty roles",
		`{"schema":"polypkg.trust/v2","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","keys":[{"id":"3a1f5c9e2b7d04a8","pubkey":"p","roles":[]}]}`),
	Entry("unknown field",
		`{"schema":"polypkg.trust/v2","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","keys":[{"id":"3a1f5c9e2b7d04a8","pubkey":"p","roles":["index"]}],"extra":true}`),
	Entry("key extra field",
		`{"schema":"polypkg.trust/v2","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","keys":[{"id":"3a1f5c9e2b7d04a8","pubkey":"p","roles":["index"],"x":1}]}`),
	Entry("bad revoked entry",
		`{"schema":"polypkg.trust/v2","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","keys":[{"id":"3a1f5c9e2b7d04a8","pubkey":"p","roles":["index"]}],"revoked":["ZZ"]}`),
)
