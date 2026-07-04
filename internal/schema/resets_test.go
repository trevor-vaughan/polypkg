package schema_test

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("Resets", func() {
	It("round-trips a valid record", func() {
		doc := `{"schema":"polypkg.resets/v1","scope":"user","paths":["hello/etc/app.conf"]}`
		r, err := schema.ParseResets(strings.NewReader(doc))
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Scope).To(Equal("user"))
		Expect(r.Paths).To(Equal([]string{"hello/etc/app.conf"}))
	})

	It("rejects an unknown schema string", func() {
		doc := `{"schema":"polypkg.resets/v2","scope":"user","paths":["x"]}`
		_, err := schema.ParseResets(strings.NewReader(doc))
		Expect(err).To(HaveOccurred())
	})

	It("rejects duplicate paths", func() {
		doc := `{"schema":"polypkg.resets/v1","scope":"user","paths":["x","x"]}`
		_, err := schema.ParseResets(strings.NewReader(doc))
		Expect(err).To(HaveOccurred())
	})

	It("rejects a missing required field", func() {
		doc := `{"schema":"polypkg.resets/v1","scope":"user"}`
		_, err := schema.ParseResets(strings.NewReader(doc))
		Expect(err).To(HaveOccurred())
	})

	It("normalizes a nil paths array to empty", func() {
		doc := `{"schema":"polypkg.resets/v1","scope":"user","paths":[]}`
		r, err := schema.ParseResets(strings.NewReader(doc))
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Paths).NotTo(BeNil())
		Expect(r.Paths).To(BeEmpty())
	})
})
