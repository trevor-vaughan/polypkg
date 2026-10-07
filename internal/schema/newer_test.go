package schema

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("newer-schema detection", func() {
	It("names the kind, both versions, and the fix", func() {
		_, err := ParseOwnership(strings.NewReader(
			`{"schema":"polypkg.ownership/v2","scope":"user","entries":[],"future":true}`))
		var ne *NewerSchemaError
		Expect(errors.As(err, &ne)).To(BeTrue(), "got %v", err)
		Expect(ne.Found).To(Equal("polypkg.ownership/v2"))
		Expect(ne.Supported).To(Equal(1))
		Expect(ne.Path).To(BeEmpty())
		Expect(err.Error()).To(Equal(
			"this document was written by a newer polypkg (polypkg.ownership/v2; this version reads v1); upgrade polypkg"))
	})

	DescribeTable("detects it for every on-disk state kind",
		func(parse func(io.Reader) error, doc, found string, supported int) {
			err := parse(strings.NewReader(doc))
			var ne *NewerSchemaError
			Expect(errors.As(err, &ne)).To(BeTrue(), "got %v", err)
			Expect(ne.Found).To(Equal(found))
			Expect(ne.Supported).To(Equal(supported))
		},
		Entry("manifest", func(r io.Reader) error { _, err := ParseManifest(r); return err },
			`{"schema":"polypkg.manifest/v3"}`, "polypkg.manifest/v3", 2),
		Entry("ownership", func(r io.Reader) error { _, err := ParseOwnership(r); return err },
			`{"schema":"polypkg.ownership/v10"}`, "polypkg.ownership/v10", 1),
		Entry("pin", func(r io.Reader) error { _, err := ParsePin(r); return err },
			`{"schema":"polypkg.pin/v2"}`, "polypkg.pin/v2", 1),
		Entry("accepted drift", func(r io.Reader) error { _, err := ParseAcceptedDrift(r); return err },
			`{"schema":"polypkg.accepted-drift/v2"}`, "polypkg.accepted-drift/v2", 1),
		Entry("resets", func(r io.Reader) error { _, err := ParseResets(r); return err },
			`{"schema":"polypkg.resets/v2"}`, "polypkg.resets/v2", 1),
	)

	// A newer publisher's document usually carries fields this binary does not
	// know, so the check must run before the strict (DisallowUnknownFields)
	// decode, or the user sees "unknown field" instead of "upgrade polypkg".
	DescribeTable("detects it for every fetched document kind, ahead of strict decoding",
		func(parse func(io.Reader) error, doc, found string, supported int) {
			err := parse(strings.NewReader(doc))
			var ne *NewerSchemaError
			Expect(errors.As(err, &ne)).To(BeTrue(), "got %v", err)
			Expect(ne.Found).To(Equal(found))
			Expect(ne.Supported).To(Equal(supported))
		},
		Entry("index", func(r io.Reader) error { _, err := ParseIndex(r); return err },
			`{"schema":"polypkg.index/v4","expires":"2099-01-01T00:00:00Z","packages":{},"future":true}`, "polypkg.index/v4", 3),
		Entry("trust document", func(r io.Reader) error { _, err := ParseTrustDoc(r); return err },
			`{"schema":"polypkg.trust/v3","future":true}`, "polypkg.trust/v3", 2),
		Entry("trust bundle", func(r io.Reader) error { _, err := ParseTrustBundle(r); return err },
			`{"schema":"polypkg.trust-bundle/v2","future":true}`, "polypkg.trust-bundle/v2", 1),
		Entry("revocation list", func(r io.Reader) error { _, err := ParseRevocationList(r); return err },
			`{"schema":"polypkg.revocation-list/v2","future":true}`, "polypkg.revocation-list/v2", 1),
		Entry("pool manifest", func(r io.Reader) error { _, err := ParsePoolManifest(r); return err },
			`{"schema":"polypkg.pool-manifest/v2","future":true}`, "polypkg.pool-manifest/v2", 1),
	)

	DescribeTable("leaves every other failure to strict validation",
		func(doc string) {
			_, err := ParseOwnership(strings.NewReader(doc))
			Expect(err).To(HaveOccurred(), "the pre-check must never accept a document")
			var ne *NewerSchemaError
			Expect(errors.As(err, &ne)).To(BeFalse(), "got %v", err)
		},
		Entry("same version, additive field", `{"schema":"polypkg.ownership/v1","scope":"user","entries":[],"x":1}`),
		Entry("another kind at a higher version", `{"schema":"polypkg.pin/v9","scope":"user","entries":[]}`),
		Entry("non-numeric version", `{"schema":"polypkg.ownership/vX","scope":"user","entries":[]}`),
		Entry("signed version", `{"schema":"polypkg.ownership/v+2","scope":"user","entries":[]}`),
		Entry("empty version", `{"schema":"polypkg.ownership/v","scope":"user","entries":[]}`),
		Entry("foreign prefix", `{"schema":"other.ownership/v2","scope":"user","entries":[]}`),
		Entry("non-string schema", `{"schema":2,"scope":"user","entries":[]}`),
		Entry("no schema field", `{"scope":"user","entries":[]}`),
		Entry("not JSON", `not json`),
	)

	It("treats a version too large to parse as newer", func() {
		_, err := ParseOwnership(strings.NewReader(`{"schema":"polypkg.ownership/v99999999999999999999"}`))
		var ne *NewerSchemaError
		Expect(errors.As(err, &ne)).To(BeTrue(), "got %v", err)
		Expect(ne.Found).To(Equal("polypkg.ownership/v99999999999999999999"))
	})

	It("leaves an older version to strict validation", func() {
		_, err := ParseManifest(strings.NewReader(`{"schema":"polypkg.manifest/v1"}`))
		Expect(err).To(HaveOccurred())
		var ne *NewerSchemaError
		Expect(errors.As(err, &ne)).To(BeFalse(), "got %v", err)
	})

	Describe("WithPath", func() {
		newer := func() error {
			_, err := ParsePin(strings.NewReader(`{"schema":"polypkg.pin/v2"}`))
			return err
		}

		It("names the file in the message", func() {
			err := WithPath(newer(), "/state/generations/3/pin.json")
			Expect(err.Error()).To(Equal(
				"/state/generations/3/pin.json was written by a newer polypkg (polypkg.pin/v2; this version reads v1); upgrade polypkg"))
		})

		It("reaches through %w wrappers", func() {
			err := WithPath(fmt.Errorf("parse pin.json: %w", newer()), "/p/pin.json")
			var ne *NewerSchemaError
			Expect(errors.As(err, &ne)).To(BeTrue())
			Expect(ne.Path).To(Equal("/p/pin.json"))
		})

		It("keeps the first path attached", func() {
			err := WithPath(WithPath(newer(), "/first"), "/second")
			var ne *NewerSchemaError
			Expect(errors.As(err, &ne)).To(BeTrue())
			Expect(ne.Path).To(Equal("/first"))
		})

		It("returns other errors and nil unchanged", func() {
			plain := errors.New("boom")
			Expect(WithPath(plain, "/p")).To(BeIdenticalTo(plain))
			Expect(WithPath(nil, "/p")).To(BeNil())
		})
	})

	DescribeTable("parseSchemaID",
		func(id, kind string, version int, ok bool) {
			k, v, gotOK := parseSchemaID(id)
			Expect(gotOK).To(Equal(ok))
			Expect(k).To(Equal(kind))
			Expect(v).To(Equal(version))
		},
		Entry("plain", "polypkg.ownership/v1", "polypkg.ownership", 1, true),
		Entry("hyphenated kind", "polypkg.accepted-drift/v12", "polypkg.accepted-drift", 12, true),
		Entry("zero version", "polypkg.ownership/v0", "", 0, false),
		Entry("leading sign", "polypkg.ownership/v+1", "", 0, false),
		Entry("no version", "polypkg.ownership", "", 0, false),
		Entry("empty kind", "polypkg./v1", "", 0, false),
		Entry("foreign prefix", "acme.ownership/v1", "", 0, false),
		Entry("overflow reads as newer than any version", "polypkg.ownership/v99999999999999999999", "polypkg.ownership", math.MaxInt, true),
	)
})
