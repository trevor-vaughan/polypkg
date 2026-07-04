package attest_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/attest"
)

var _ = Describe("AssembleLinkStatement", func() {
	It("binds the artifact blake3 subject to the carried materials and round-trips", func() {
		st, err := attest.AssembleLinkStatement("hello-1.0.0.tar.zst", "deadbeef", []attest.LinkMaterial{
			{Name: "content:bin/hello", Digest: map[string]string{"sha256": "cafe"}},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(st.Type).To(Equal("https://in-toto.io/Statement/v1"))
		Expect(st.PredicateType).To(Equal(attest.PredicateTypePolypkgLink))
		Expect(st.Subject).To(HaveLen(1))
		Expect(st.Subject[0].Name).To(Equal("hello-1.0.0.tar.zst"))
		Expect(st.Subject[0].Digest["blake3"]).To(Equal("deadbeef"))

		b, err := st.CanonicalJSON()
		Expect(err).NotTo(HaveOccurred())
		got, err := attest.ParseStatement(b)
		Expect(err).NotTo(HaveOccurred())
		Expect(got.PredicateType).To(Equal(attest.PredicateTypePolypkgLink))
		Expect(string(got.Predicate)).To(ContainSubstring("content:bin/hello"))
		Expect(string(got.Predicate)).To(ContainSubstring("cafe"))
	})
})
