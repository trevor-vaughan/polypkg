package trust

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("parseComment", func() {
	DescribeTable("parse results",
		func(input string, ok bool, check func(map[string]string)) {
			m, err := parseComment(input)
			if ok {
				Expect(err).NotTo(HaveOccurred())
				check(m)
			} else {
				Expect(err).To(HaveOccurred())
			}
		},
		Entry("artifact fields",
			"name=hello version=1.0.0 hash=blake3:abc123",
			true,
			func(m map[string]string) {
				Expect(m).To(Equal(map[string]string{
					"name":    "hello",
					"version": "1.0.0",
					"hash":    "blake3:abc123",
				}))
			},
		),
		Entry("index fields",
			"serial=42 ts=2026-05-25T00:00:00Z",
			true,
			func(m map[string]string) {
				Expect(m["serial"]).To(Equal("42"))
				Expect(m["ts"]).To(Equal("2026-05-25T00:00:00Z"))
			},
		),
		Entry("empty value allowed",
			"k=",
			true,
			func(m map[string]string) {
				Expect(m["k"]).To(Equal(""))
			},
		),
		Entry("rejects token without equals", "name hello", false, nil),
		Entry("rejects empty key", "=v", false, nil),
		Entry("rejects duplicate key", "name=a name=b", false, nil),
	)
})
