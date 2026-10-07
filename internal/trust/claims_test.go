package trust

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Claims.Attestation", func() {
	It("returns the bound name, version and hash without requiring a platform", func() {
		c := Claims{Values: map[string]string{"name": "hello", "version": "1.0.0", "hash": "blake3:abc"}}
		n, v, h, err := c.Attestation()
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal("hello"))
		Expect(v).To(Equal("1.0.0"))
		Expect(h).To(Equal("blake3:abc"))
	})

	DescribeTable("refuses an incomplete or non-blake3 claim",
		func(values map[string]string, wantSubstr string) {
			_, _, _, err := Claims{Values: values}.Attestation()
			Expect(err).To(MatchError(ContainSubstring(wantSubstr)))
		},
		Entry("missing name",
			map[string]string{"version": "1.0.0", "hash": "blake3:abc"},
			"attestation signature comment missing name/version/hash"),
		Entry("missing version",
			map[string]string{"name": "hello", "hash": "blake3:abc"},
			"attestation signature comment missing name/version/hash"),
		Entry("missing hash",
			map[string]string{"name": "hello", "version": "1.0.0"},
			"attestation signature comment missing name/version/hash"),
		Entry("non-blake3 hash",
			map[string]string{"name": "hello", "version": "1.0.0", "hash": "sha256:abc"},
			`attestation signature comment hash "sha256:abc" is not a blake3 digest`),
		Entry("bare blake3 prefix",
			map[string]string{"name": "hello", "version": "1.0.0", "hash": "blake3:"},
			`attestation signature comment hash "blake3:" is not a blake3 digest`),
	)
})

var _ = Describe("Claims.Artifact", func() {
	withPlatform := func(plat string) map[string]string {
		return map[string]string{"name": "hello", "version": "1.0.0", "platform": plat, "hash": "blake3:abc"}
	}

	DescribeTable("accepts a well-formed platform claim",
		func(claimed, want string) {
			n, v, p, h, err := Claims{Values: withPlatform(claimed)}.Artifact()
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal("hello"))
			Expect(v).To(Equal("1.0.0"))
			Expect(p).To(Equal(want))
			Expect(h).To(Equal("blake3:abc"))
		},
		Entry("reserved any token reads as platform-agnostic", "any", ""),
		Entry("producer platform", "linux/amd64", "linux/amd64"),
		Entry("variant segment (consumer grammar)", "linux/arm/v7", "linux/arm/v7"),
		Entry("well-formed platform outside this toolchain's allow-list", "plan9/mips", "plan9/mips"),
	)

	DescribeTable("refuses a missing or malformed platform claim",
		func(values map[string]string, wantSubstr string) {
			_, _, _, _, err := Claims{Values: values}.Artifact()
			Expect(err).To(MatchError(ContainSubstring(wantSubstr)))
		},
		Entry("platform field absent (a replayable pre-platform signature)",
			map[string]string{"name": "hello", "version": "1.0.0", "hash": "blake3:abc"},
			"artifact signature comment missing platform"),
		Entry("empty platform value",
			withPlatform(""), "artifact signature comment missing platform"),
		Entry("uppercase os", withPlatform("Linux/amd64"), `artifact signature comment: platform "Linux/amd64" is not <os>/<arch>`),
		Entry("single segment", withPlatform("linux"), `artifact signature comment: platform "linux" is not <os>/<arch>`),
		Entry("four segments", withPlatform("linux/arm/v7/x"), `artifact signature comment: platform "linux/arm/v7/x" is not <os>/<arch>`),
		Entry("path traversal", withPlatform("../etc"), `artifact signature comment: platform "../etc" is not <os>/<arch>`),
		Entry("reserved token is case-sensitive", withPlatform("ANY"), `artifact signature comment: platform "ANY" is not <os>/<arch>`),
		Entry("name/version/hash still required",
			map[string]string{"version": "1.0.0", "platform": "any", "hash": "blake3:abc"},
			"artifact signature comment missing name/version/hash"),
	)

	It("quotes an untrusted malformed platform exactly once", func() {
		_, _, _, _, err := Claims{Values: withPlatform("../etc")}.Artifact()
		Expect(err).To(HaveOccurred())
		Expect(strings.Count(err.Error(), `"../etc"`)).To(Equal(1), err.Error())
	})
})
