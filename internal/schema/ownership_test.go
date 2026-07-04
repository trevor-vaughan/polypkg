package schema

import (
	"bytes"
	"encoding/json"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OwnershipEntry source_hash", func() {
	It("round-trips an entry carrying source_hash through the v1 schema", func() {
		doc := `{
  "schema": "polypkg.ownership/v1",
  "scope": "user",
  "entries": [
    {
      "path": "hello/etc/app.conf",
      "package": "hello",
      "version": "1.0.0",
      "action": "config",
      "expected": {
        "file_type": "regular",
        "content_hash": "blake3:aa",
        "source_hash": "blake3:bb"
      },
      "drift_policy": "notify_preserve",
      "stat": {"size": 1, "mtime_ns": 2, "inode": 3}
    }
  ]
}`
		own, err := ParseOwnership(strings.NewReader(doc))
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Expected.SourceHash).To(Equal("blake3:bb"))
		Expect(own.Entries[0].Action).To(Equal("config"))
	})
})

func validOwnership() *Ownership {
	return &Ownership{
		Schema: "polypkg.ownership/v1",
		Scope:  "user",
		Entries: []OwnershipEntry{{
			Path:        "hello/bin/hi",
			Package:     "hello",
			Version:     "1.0.0",
			Action:      "install",
			Expected:    Expected{FileType: "symlink", ContentHash: "blake3:abc"},
			DriftPolicy: "notify_heal",
			Stat:        StatInfo{Size: 10, MtimeNs: 123, Inode: 99},
		}},
	}
}

var _ = Describe("ParseOwnership", func() {
	It("round-trips a valid document", func() {
		data, err := json.Marshal(validOwnership())
		Expect(err).NotTo(HaveOccurred())
		got, err := ParseOwnership(bytes.NewReader(data))
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(validOwnership()))
	})

	It("accepts an empty entries array and preserves non-nil slice", func() {
		data := []byte(`{"schema":"polypkg.ownership/v1","scope":"user","entries":[]}`)
		got, err := ParseOwnership(bytes.NewReader(data))
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Entries).NotTo(BeNil())
		Expect(got.Entries).To(BeEmpty())
	})

	It("rejects a bad drift_policy", func() {
		o := validOwnership()
		o.Entries[0].DriftPolicy = "explode"
		data, err := json.Marshal(o)
		Expect(err).NotTo(HaveOccurred())
		_, err = ParseOwnership(bytes.NewReader(data))
		Expect(err).To(HaveOccurred())
		Expect(strings.ToLower(err.Error())).To(ContainSubstring("schema validation"))
	})

	It("rejects a bad file_type", func() {
		o := validOwnership()
		o.Entries[0].Expected.FileType = "device"
		data, err := json.Marshal(o)
		Expect(err).NotTo(HaveOccurred())
		_, err = ParseOwnership(bytes.NewReader(data))
		Expect(err).To(HaveOccurred())
	})

	It("rejects a document missing required fields", func() {
		data := []byte(`{"schema":"polypkg.ownership/v1","scope":"user"}`)
		_, err := ParseOwnership(bytes.NewReader(data))
		Expect(err).To(HaveOccurred())
	})
})
