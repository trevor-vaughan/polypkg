package trust

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Seen", func() {
	It("returns zero on first read (trust-on-first-use) and roundtrips after store", func() {
		dir := GinkgoT().TempDir()

		s, err := LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(s).To(Equal(Seen{}))

		Expect(StoreSeen(dir, "native", Seen{TrustSerial: 7, IndexSerial: 42})).To(Succeed())
		got, err := LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(Seen{TrustSerial: 7, IndexSerial: 42}))
	})

	It("round-trips the per-package version high-water marks", func() {
		dir := GinkgoT().TempDir()
		s := Seen{
			TrustSerial: 3,
			IndexSerial: 4,
			Packages:    map[string]string{"hello": "2.0.0", "lib": "1.4.7"},
		}
		Expect(StoreSeen(dir, "native", s)).To(Succeed())
		got, err := LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(s))
	})

	It("isolates state per source", func() {
		dir := GinkgoT().TempDir()
		Expect(StoreSeen(dir, "native", Seen{TrustSerial: 1, IndexSerial: 1})).To(Succeed())
		Expect(StoreSeen(dir, "rpm", Seen{TrustSerial: 9, IndexSerial: 9})).To(Succeed())
		a, err := LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		b, err := LoadSeen(dir, "rpm")
		Expect(err).NotTo(HaveOccurred())
		Expect(a.TrustSerial).To(Equal(uint64(1)))
		Expect(b.TrustSerial).To(Equal(uint64(9)))
	})
})
