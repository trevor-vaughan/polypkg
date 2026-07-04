package schema

import (
	"bytes"
	"encoding/json"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func validAcceptedDrift() *AcceptedDrift {
	return &AcceptedDrift{
		Schema:     "polypkg.accepted-drift/v1",
		Generation: 42,
		Paths: map[string]AcceptedPath{
			"hello/bin/hi": {
				Expected: Expected{FileType: "symlink", ContentHash: "blake3:abc"},
				Stat:     StatInfo{Size: 1, MtimeNs: 2, Inode: 3},
			},
		},
	}
}

var _ = Describe("ParseAcceptedDrift", func() {
	It("round-trips a valid document", func() {
		data, err := json.Marshal(validAcceptedDrift())
		Expect(err).NotTo(HaveOccurred())
		got, err := ParseAcceptedDrift(bytes.NewReader(data))
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(validAcceptedDrift()))
	})

	It("accepts an empty paths map", func() {
		data := []byte(`{"schema":"polypkg.accepted-drift/v1","generation":1,"paths":{}}`)
		got, err := ParseAcceptedDrift(bytes.NewReader(data))
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Paths).NotTo(BeNil())
		Expect(got.Paths).To(BeEmpty())
	})

	It("rejects a bad file_type", func() {
		o := validAcceptedDrift()
		o.Paths["hello/bin/hi"] = AcceptedPath{Expected: Expected{FileType: "device"}, Stat: StatInfo{}}
		data, err := json.Marshal(o)
		Expect(err).NotTo(HaveOccurred())
		_, err = ParseAcceptedDrift(bytes.NewReader(data))
		Expect(err).To(HaveOccurred())
		Expect(strings.ToLower(err.Error())).To(ContainSubstring("schema validation"))
	})

	It("rejects a document missing required fields", func() {
		data := []byte(`{"schema":"polypkg.accepted-drift/v1","generation":1}`)
		_, err := ParseAcceptedDrift(bytes.NewReader(data))
		Expect(err).To(HaveOccurred())
	})
})
