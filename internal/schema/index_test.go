package schema

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParseIndex", func() {
	It("parses a valid index with dependencies and provides", func() {
		src := `{
  "schema": "polypkg.index/v3",
  "expires": "2099-01-01T00:00:00Z",
  "packages": {
    "python-utils": [
      {"version":"1.2.4","content_hash":"blake3:aa","artifact":"python-utils-1.2.4.tar.zst",
       "depends":[{"name":"libyaml","version":"^0.2"}],
       "provides":[{"name":"yaml-parser"}]}
    ]
  }
}`
		idx, err := ParseIndex(strings.NewReader(src))
		Expect(err).NotTo(HaveOccurred())
		Expect(idx.Expires).To(Equal("2099-01-01T00:00:00Z"))
		e := idx.Packages["python-utils"]
		Expect(e).To(HaveLen(1))
		Expect(e[0].Version).To(Equal("1.2.4"))
		Expect(e[0].ContentHash).To(Equal("blake3:aa"))
		Expect(e[0].Depends[0].Name).To(Equal("libyaml"))
		Expect(e[0].Provides[0].Name).To(Equal("yaml-parser"))
	})

	It("rejects an unknown top-level field", func() {
		src := `{"schema":"polypkg.index/v3","expires":"2099-01-01T00:00:00Z","packages":{},"evil":true}`
		_, err := ParseIndex(strings.NewReader(src))
		Expect(err).To(HaveOccurred())
	})

	It("rejects the wrong schema id", func() {
		src := `{"schema":"polypkg.index/v1","expires":"2099-01-01T00:00:00Z","packages":{}}`
		_, err := ParseIndex(strings.NewReader(src))
		Expect(err).To(HaveOccurred())
	})

	It("rejects an index without expires", func() {
		src := `{"schema":"polypkg.index/v3","packages":{}}`
		_, err := ParseIndex(strings.NewReader(src))
		Expect(err).To(HaveOccurred())
	})

	It("rejects a package entry missing content_hash", func() {
		src := `{"schema":"polypkg.index/v3","expires":"2099-01-01T00:00:00Z","packages":{"x":[{"version":"1.0.0","artifact":"x-1.0.0.tar.zst"}]}}`
		_, err := ParseIndex(strings.NewReader(src))
		Expect(err).To(HaveOccurred())
	})

	It("parses recommends and suggests on an index entry", func() {
		src := `{
  "schema": "polypkg.index/v3",
  "expires": "2099-01-01T00:00:00Z",
  "packages": {
    "foo": [
      {
        "version": "1.0.0",
        "content_hash": "blake3:aa",
        "artifact": "foo-1.0.0.tar.zst",
        "recommends": [{"name": "foo-extras"}],
        "suggests": [{"name": "foo-docs"}]
      }
    ]
  }
}`
		idx, err := ParseIndex(strings.NewReader(src))
		Expect(err).NotTo(HaveOccurred())
		e := idx.Packages["foo"][0]
		Expect(e.Recommends).To(HaveLen(1))
		Expect(e.Recommends[0].Name).To(Equal("foo-extras"))
		Expect(e.Suggests).To(HaveLen(1))
		Expect(e.Suggests[0].Name).To(Equal("foo-docs"))
	})

	It("parses revision and attestations on an index entry", func() {
		src := `{
  "schema": "polypkg.index/v3",
  "expires": "2099-01-01T00:00:00Z",
  "packages": {
    "foo": [
      {
        "version": "1.0.0",
        "content_hash": "blake3:aa",
        "artifact": "pool/aa.tar.zst",
        "revision": 2,
        "attestations": [
          {"predicate_type": "https://docs.oasis-open.org/sarif/sarif/v2.1.0",
           "artifact": "pool/bb.att.json",
           "content_hash": "blake3:bb"}
        ]
      }
    ]
  }
}`
		idx, err := ParseIndex(strings.NewReader(src))
		Expect(err).NotTo(HaveOccurred())
		e := idx.Packages["foo"][0]
		Expect(e.Revision).To(Equal(2))
		Expect(e.Attestations).To(HaveLen(1))
		Expect(e.Attestations[0].Artifact).To(Equal("pool/bb.att.json"))
		Expect(e.Attestations[0].ContentHash).To(Equal("blake3:bb"))
	})

	It("rejects an attestation missing content_hash", func() {
		src := `{"schema":"polypkg.index/v3","expires":"2099-01-01T00:00:00Z","packages":{"x":[{"version":"1.0.0","content_hash":"blake3:aa","artifact":"pool/aa.tar.zst","attestations":[{"predicate_type":"p","artifact":"pool/bb.att.json"}]}]}}`
		_, err := ParseIndex(strings.NewReader(src))
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("AttestationRef carriage fields", func() {
	const withCarriage = `{
      "schema": "polypkg.index/v3",
      "expires": "2099-01-01T00:00:00Z",
      "packages": {
        "hello": [{
          "version": "1.0.0",
          "content_hash": "blake3:aa",
          "artifact": "pool/aa.tar.zst",
          "attestations": [{
            "predicate_type": "https://slsa.dev/provenance/v1",
            "artifact": "pool/bb.att.json",
            "content_hash": "blake3:bb",
            "kind": "carried-opaque",
            "format": "slsa-provenance",
            "subject_scope": "content:bin/hello",
            "subject_digests": { "sha256": "cafe" }
          }]
        }]
      }
    }`

	It("parses an attestation ref carrying kind/format/subject fields", func() {
		idx, err := ParseIndex(strings.NewReader(withCarriage))
		Expect(err).NotTo(HaveOccurred())
		ref := idx.Packages["hello"][0].Attestations[0]
		Expect(ref.Kind).To(Equal("carried-opaque"))
		Expect(ref.Format).To(Equal("slsa-provenance"))
		Expect(ref.SubjectScope).To(Equal("content:bin/hello"))
		Expect(ref.SubjectDigests).To(Equal(map[string]string{"sha256": "cafe"}))
	})

	It("parses an attestation ref WITHOUT the new fields (backward compatible)", func() {
		const legacy = `{
          "schema": "polypkg.index/v3",
          "expires": "2099-01-01T00:00:00Z",
          "packages": { "hello": [{
            "version": "1.0.0", "content_hash": "blake3:aa", "artifact": "pool/aa.tar.zst",
            "attestations": [{ "predicate_type": "x", "artifact": "pool/bb.att.json", "content_hash": "blake3:bb" }]
          }]}
        }`
		idx, err := ParseIndex(strings.NewReader(legacy))
		Expect(err).NotTo(HaveOccurred())
		ref := idx.Packages["hello"][0].Attestations[0]
		Expect(ref.Kind).To(BeEmpty())
		Expect(ref.SubjectDigests).To(BeNil())
	})

	It("accepts every declared kind and format constant", func() {
		for _, kind := range []string{KindNativeJCS, KindCarriedOpaque} {
			doc := strings.Replace(withCarriage, `"kind": "carried-opaque"`, `"kind": "`+kind+`"`, 1)
			_, err := ParseIndex(strings.NewReader(doc))
			Expect(err).NotTo(HaveOccurred(), "kind %q should validate", kind)
		}
		for _, format := range []string{
			FormatPolypkgSARIF, FormatPolypkgLink, FormatSLSAProvenance, FormatSPDX,
			FormatCycloneDX, FormatInTotoGeneric, FormatInTotoUnclassified, FormatSigstoreBundle,
		} {
			doc := strings.Replace(withCarriage, `"format": "slsa-provenance"`, `"format": "`+format+`"`, 1)
			_, err := ParseIndex(strings.NewReader(doc))
			Expect(err).NotTo(HaveOccurred(), "format %q should validate", format)
		}
	})
})

var _ = DescribeTable("ParseIndex rejects invalid carriage fields",
	func(mutate func(string) string) {
		const base = `{
          "schema": "polypkg.index/v3", "expires": "2099-01-01T00:00:00Z",
          "packages": { "hello": [{
            "version": "1.0.0", "content_hash": "blake3:aa", "artifact": "pool/aa.tar.zst",
            "attestations": [{ "predicate_type": "x", "artifact": "pool/bb.att.json", "content_hash": "blake3:bb", "kind": "native-jcs", "format": "polypkg-sarif", "subject_scope": "artifact" }]
          }]}
        }`
		_, err := ParseIndex(strings.NewReader(mutate(base)))
		Expect(err).To(HaveOccurred())
	},
	Entry("bad kind enum", func(s string) string { return strings.Replace(s, `"kind": "native-jcs"`, `"kind": "bogus"`, 1) }),
	Entry("bad format enum", func(s string) string {
		return strings.Replace(s, `"format": "polypkg-sarif"`, `"format": "made-up"`, 1)
	}),
	Entry("bad subject_scope pattern", func(s string) string {
		return strings.Replace(s, `"subject_scope": "artifact"`, `"subject_scope": "whole-thing"`, 1)
	}),
	Entry("unknown attestation field", func(s string) string {
		return strings.Replace(s, `"kind": "native-jcs"`, `"kind": "native-jcs", "smuggled": true`, 1)
	}),
)
