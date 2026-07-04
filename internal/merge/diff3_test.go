package merge_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/merge"
)

var _ = Describe("Merge", func() {
	It("returns the common content unchanged when all three are identical", func() {
		base := []byte("a\nb\nc\n")
		res, err := merge.Merge(base, base, base)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Conflicts).To(Equal(0))
		Expect(string(res.Merged)).To(Equal("a\nb\nc\n"))
	})

	It("takes live's change when only live changed", func() {
		base := []byte("a\nb\nc\n")
		live := []byte("a\nB\nc\n")
		inc := []byte("a\nb\nc\n")
		res, err := merge.Merge(base, live, inc)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Conflicts).To(Equal(0))
		Expect(string(res.Merged)).To(Equal("a\nB\nc\n"))
	})

	It("takes incoming's change when only incoming changed", func() {
		base := []byte("a\nb\nc\n")
		live := []byte("a\nb\nc\n")
		inc := []byte("a\nb\nC\n")
		res, err := merge.Merge(base, live, inc)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Conflicts).To(Equal(0))
		Expect(string(res.Merged)).To(Equal("a\nb\nC\n"))
	})

	It("merges non-overlapping additions from both sides", func() {
		base := []byte("a\nb\nc\n")
		live := []byte("HEAD\na\nb\nc\n")
		inc := []byte("a\nb\nc\nTAIL\n")
		res, err := merge.Merge(base, live, inc)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Conflicts).To(Equal(0))
		Expect(string(res.Merged)).To(Equal("HEAD\na\nb\nc\nTAIL\n"))
	})

	It("emits a single copy when both sides made the same change", func() {
		base := []byte("a\nc\n")
		live := []byte("a\nb\nc\n")
		inc := []byte("a\nb\nc\n")
		res, err := merge.Merge(base, live, inc)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Conflicts).To(Equal(0))
		Expect(string(res.Merged)).To(Equal("a\nb\nc\n"))
	})

	It("emits conflict markers when both sides changed the same region differently", func() {
		base := []byte("a\nb\nc\n")
		live := []byte("a\nLIVE\nc\n")
		inc := []byte("a\nINCOMING\nc\n")
		res, err := merge.Merge(base, live, inc)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Conflicts).To(Equal(1))
		Expect(string(res.Merged)).To(Equal(
			"a\n<<<<<<< LIVE\nLIVE\n=======\nINCOMING\n>>>>>>> INCOMING\nc\n"))
	})

	It("counts multiple independent conflicts", func() {
		base := []byte("a\nb\nc\nd\ne\n")
		live := []byte("a\nB1\nc\nD1\ne\n")
		inc := []byte("a\nB2\nc\nD2\ne\n")
		res, err := merge.Merge(base, live, inc)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Conflicts).To(Equal(2))
	})

	It("conflicts over the entire output when base is empty and both add different lines", func() {
		res, err := merge.Merge(nil, []byte("X\n"), []byte("Y\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Conflicts).To(Equal(1))
		Expect(string(res.Merged)).To(Equal(
			"<<<<<<< LIVE\nX\n=======\nY\n>>>>>>> INCOMING\n"))
	})

	It("omits the trailing newline when incoming has none", func() {
		base := []byte("a\nb\n")
		live := []byte("a\nB\n")
		inc := []byte("a\nb") // no trailing newline
		res, err := merge.Merge(base, live, inc)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(res.Merged)).To(Equal("a\nB"))
	})

	It("adds a trailing newline when incoming has one but the merged tail lacks it", func() {
		base := []byte("a\nb")
		live := []byte("a\nB")
		inc := []byte("a\nb\n") // trailing newline present
		res, err := merge.Merge(base, live, inc)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(res.Merged)).To(Equal("a\nB\n"))
	})
})
