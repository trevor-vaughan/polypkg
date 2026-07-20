package schema

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const validTrustBundle = `{
  "schema": "polypkg.trust-bundle/v1",
  "source": "native",
  "serial": 4,
  "issued_at": "2026-05-25T00:00:00Z",
  "expires": "2099-01-01T00:00:00Z",
  "builder_keys": [
    {
      "key_id": "builder-a",
      "public_key": "cHVia2V5",
      "algo": "ed25519",
      "valid_from": "2026-01-01T00:00:00Z",
      "valid_until": "2027-01-01T00:00:00Z",
      "superseded_by": "builder-b"
    }
  ],
  "sigstore_roots": [
    {
      "valid_from": "2026-01-01T00:00:00Z",
      "fulcio_ca": ["ZnVsY2lv"],
      "rekor_keys": ["cmVrb3I="],
      "ctlog_keys": ["Y3Rsb2c="]
    }
  ]
}`

var _ = Describe("ParseTrustBundle", func() {
	It("parses a valid trust bundle", func() {
		b, err := ParseTrustBundle(strings.NewReader(validTrustBundle))
		Expect(err).NotTo(HaveOccurred())
		Expect(b.Schema).To(Equal("polypkg.trust-bundle/v1"))
		Expect(b.Source).To(Equal("native"))
		Expect(b.Serial).To(Equal(uint64(4)))
		Expect(b.Expires).To(Equal("2099-01-01T00:00:00Z"))
		Expect(b.BuilderKeys).To(HaveLen(1))
		Expect(b.BuilderKeys[0].KeyID).To(Equal("builder-a"))
		Expect(b.BuilderKeys[0].Algo).To(Equal("ed25519"))
		Expect(b.BuilderKeys[0].ValidFrom).To(Equal("2026-01-01T00:00:00Z"))
		Expect(b.BuilderKeys[0].ValidUntil).To(Equal("2027-01-01T00:00:00Z"))
		Expect(b.BuilderKeys[0].SupersededBy).To(Equal("builder-b"))
		Expect(b.SigstoreRoots).To(HaveLen(1))
		Expect(b.SigstoreRoots[0].FulcioCA).To(Equal([]string{"ZnVsY2lv"}))
		Expect(b.SigstoreRoots[0].RekorKeys).To(Equal([]string{"cmVrb3I="}))
	})

	It("parses an empty bundle (no builder keys or sigstore roots)", func() {
		doc := `{"schema":"polypkg.trust-bundle/v1","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z"}`
		b, err := ParseTrustBundle(strings.NewReader(doc))
		Expect(err).NotTo(HaveOccurred())
		Expect(b.BuilderKeys).To(BeEmpty())
		Expect(b.SigstoreRoots).To(BeEmpty())
	})

	It("rejects a bundle with duplicate builder key_id", func() {
		doc := `{
		  "schema": "polypkg.trust-bundle/v1",
		  "source": "native",
		  "serial": 1,
		  "expires": "2099-01-01T00:00:00Z",
		  "builder_keys": [
		    {
		      "key_id": "builder-a",
		      "public_key": "cHVia2V5MQ==",
		      "algo": "ed25519",
		      "valid_from": "2020-01-01T00:00:00Z",
		      "valid_until": "2021-01-01T00:00:00Z"
		    },
		    {
		      "key_id": "builder-a",
		      "public_key": "cHVia2V5Mg==",
		      "algo": "ed25519",
		      "valid_from": "2026-01-01T00:00:00Z"
		    }
		  ]
		}`
		_, err := ParseTrustBundle(strings.NewReader(doc))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("duplicate"))
		Expect(err.Error()).To(ContainSubstring("builder-a"))
	})

	It("parses a bundle with distinct builder key_ids", func() {
		doc := `{
		  "schema": "polypkg.trust-bundle/v1",
		  "source": "native",
		  "serial": 1,
		  "expires": "2099-01-01T00:00:00Z",
		  "builder_keys": [
		    {
		      "key_id": "builder-a",
		      "public_key": "cHVia2V5MQ==",
		      "algo": "ed25519",
		      "valid_from": "2020-01-01T00:00:00Z",
		      "valid_until": "2021-01-01T00:00:00Z"
		    },
		    {
		      "key_id": "builder-b",
		      "public_key": "cHVia2V5Mg==",
		      "algo": "ed25519",
		      "valid_from": "2026-01-01T00:00:00Z"
		    }
		  ]
		}`
		b, err := ParseTrustBundle(strings.NewReader(doc))
		Expect(err).NotTo(HaveOccurred())
		Expect(b.BuilderKeys).To(HaveLen(2))
		Expect(b.BuilderKeys[0].KeyID).To(Equal("builder-a"))
		Expect(b.BuilderKeys[1].KeyID).To(Equal("builder-b"))
	})
})

var _ = DescribeTable("ParseTrustBundle rejects invalid documents",
	func(doc string) {
		_, err := ParseTrustBundle(strings.NewReader(doc))
		Expect(err).To(HaveOccurred())
	},
	Entry("wrong schema",
		`{"schema":"polypkg.trust-bundle/v2","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z"}`),
	Entry("missing expires",
		`{"schema":"polypkg.trust-bundle/v1","source":"native","serial":1}`),
	Entry("missing source",
		`{"schema":"polypkg.trust-bundle/v1","serial":1,"expires":"2099-01-01T00:00:00Z"}`),
	Entry("unknown top-level field",
		`{"schema":"polypkg.trust-bundle/v1","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","extra":true}`),
	Entry("builder key missing algo",
		`{"schema":"polypkg.trust-bundle/v1","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","builder_keys":[{"key_id":"a","public_key":"p","valid_from":"2026-01-01T00:00:00Z"}]}`),
	Entry("builder key bad algo enum",
		`{"schema":"polypkg.trust-bundle/v1","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","builder_keys":[{"key_id":"a","public_key":"p","algo":"rsa","valid_from":"2026-01-01T00:00:00Z"}]}`),
	Entry("builder key bad valid_from format",
		`{"schema":"polypkg.trust-bundle/v1","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","builder_keys":[{"key_id":"a","public_key":"p","algo":"ed25519","valid_from":"not-a-date"}]}`),
	Entry("builder key extra field",
		`{"schema":"polypkg.trust-bundle/v1","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","builder_keys":[{"key_id":"a","public_key":"p","algo":"ed25519","valid_from":"2026-01-01T00:00:00Z","x":1}]}`),
	Entry("sigstore root missing rekor_keys",
		`{"schema":"polypkg.trust-bundle/v1","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","sigstore_roots":[{"valid_from":"2026-01-01T00:00:00Z","fulcio_ca":["c"]}]}`),
	Entry("sigstore root empty fulcio_ca",
		`{"schema":"polypkg.trust-bundle/v1","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","sigstore_roots":[{"valid_from":"2026-01-01T00:00:00Z","fulcio_ca":[],"rekor_keys":["r"]}]}`),
)
