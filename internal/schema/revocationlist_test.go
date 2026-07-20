package schema

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const validRevocationList = `{
  "schema": "polypkg.revocation-list/v1",
  "source": "native",
  "serial": 2,
  "issued_at": "2026-05-25T00:00:00Z",
  "expires": "2099-01-01T00:00:00Z",
  "revoked_builder_keys": ["builder-a"],
  "revoked_attestations": ["blake3:deadbeef"]
}`

var _ = Describe("ParseRevocationList", func() {
	It("parses a valid revocation list", func() {
		rl, err := ParseRevocationList(strings.NewReader(validRevocationList))
		Expect(err).NotTo(HaveOccurred())
		Expect(rl.Schema).To(Equal("polypkg.revocation-list/v1"))
		Expect(rl.Source).To(Equal("native"))
		Expect(rl.Serial).To(Equal(uint64(2)))
		Expect(rl.Expires).To(Equal("2099-01-01T00:00:00Z"))
		Expect(rl.RevokedBuilderKeys).To(Equal([]string{"builder-a"}))
		Expect(rl.RevokedAttestations).To(Equal([]string{"blake3:deadbeef"}))
	})

	It("parses an empty revocation list", func() {
		doc := `{"schema":"polypkg.revocation-list/v1","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z"}`
		rl, err := ParseRevocationList(strings.NewReader(doc))
		Expect(err).NotTo(HaveOccurred())
		Expect(rl.RevokedBuilderKeys).To(BeEmpty())
		Expect(rl.RevokedAttestations).To(BeEmpty())
	})
})

var _ = DescribeTable("ParseRevocationList rejects invalid documents",
	func(doc string) {
		_, err := ParseRevocationList(strings.NewReader(doc))
		Expect(err).To(HaveOccurred())
	},
	Entry("wrong schema",
		`{"schema":"polypkg.revocation-list/v2","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z"}`),
	Entry("missing expires",
		`{"schema":"polypkg.revocation-list/v1","source":"native","serial":1}`),
	Entry("missing source",
		`{"schema":"polypkg.revocation-list/v1","serial":1,"expires":"2099-01-01T00:00:00Z"}`),
	Entry("unknown field",
		`{"schema":"polypkg.revocation-list/v1","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","extra":true}`),
	Entry("attestation not blake3",
		`{"schema":"polypkg.revocation-list/v1","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","revoked_attestations":["sha256:abc"]}`),
	Entry("attestation blake3 non-hex",
		`{"schema":"polypkg.revocation-list/v1","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","revoked_attestations":["blake3:ZZ"]}`),
	Entry("empty builder key string",
		`{"schema":"polypkg.revocation-list/v1","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","revoked_builder_keys":[""]}`),
)
