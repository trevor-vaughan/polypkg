package schema

import (
	"bytes"
	"encoding/json"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParseCLIResult", func() {
	It("parses an ok envelope", func() {
		in := `{"schema":"polypkg.cli-result/v2","command":"apply","status":"ok","data":{"gen_id":7}}`
		r, err := ParseCLIResult(strings.NewReader(in))
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Schema).To(Equal("polypkg.cli-result/v2"))
		Expect(r.Command).To(Equal("apply"))
		Expect(r.Status).To(Equal("ok"))
		Expect(r.Data["gen_id"]).To(BeEquivalentTo(7))
	})

	It("parses an error envelope", func() {
		in := `{"schema":"polypkg.cli-result/v2","command":"apply","status":"error","error":"oops"}`
		r, err := ParseCLIResult(strings.NewReader(in))
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Status).To(Equal("error"))
		Expect(r.Error).To(Equal("oops"))
	})

	It("rejects an unknown status value", func() {
		in := `{"schema":"polypkg.cli-result/v2","command":"apply","status":"maybe"}`
		_, err := ParseCLIResult(strings.NewReader(in))
		Expect(err).To(HaveOccurred())
	})

	It("rejects a missing command", func() {
		in := `{"schema":"polypkg.cli-result/v2","status":"ok"}`
		_, err := ParseCLIResult(strings.NewReader(in))
		Expect(err).To(HaveOccurred())
	})

	It("round-trips via Marshal", func() {
		r := &CLIResult{
			Schema:  "polypkg.cli-result/v2",
			Command: "rollback",
			Status:  "ok",
			Data:    map[string]any{"target": float64(3)},
		}
		data, err := json.Marshal(r)
		Expect(err).NotTo(HaveOccurred())
		round, err := ParseCLIResult(bytes.NewReader(data))
		Expect(err).NotTo(HaveOccurred())
		Expect(round.Command).To(Equal(r.Command))
		Expect(round.Status).To(Equal(r.Status))
		Expect(round.Data["target"]).To(Equal(float64(3)))
	})
})
