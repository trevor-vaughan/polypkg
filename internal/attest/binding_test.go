package attest_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"lukechampine.com/blake3"

	"github.com/trevor-vaughan/polypkg/internal/attest"
)

func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func sha512Hex(b []byte) string { s := sha512.Sum512(b); return hex.EncodeToString(s[:]) }
func blake3Hex(b []byte) string {
	h := blake3.New(32, nil)
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

var _ = Describe("MatchSubjectDigests", func() {
	data := []byte("the artifact bytes")

	It("binds when the single sha256 digest matches", func() {
		Expect(attest.MatchSubjectDigests(data, map[string]string{"sha256": sha256Hex(data)}, "sha256")).To(Succeed())
	})

	It("binds when every overlapping algorithm (sha256 + blake3 + sha512) agrees", func() {
		subj := map[string]string{"sha256": sha256Hex(data), "blake3": blake3Hex(data), "sha512": sha512Hex(data)}
		Expect(attest.MatchSubjectDigests(data, subj, "sha256")).To(Succeed())
	})

	It("is case-insensitive on the claimed hex", func() {
		up := map[string]string{"sha256": strings.ToUpper(sha256Hex(data))}
		Expect(attest.MatchSubjectDigests(data, up, "sha256")).To(Succeed())
	})

	It("rejects when a matched sha256 rides alongside a mismatched sha512 (tamper)", func() {
		subj := map[string]string{"sha256": sha256Hex(data), "sha512": sha512Hex([]byte("other"))}
		err := attest.MatchSubjectDigests(data, subj, "sha256")
		Expect(err).To(MatchError(ContainSubstring("sha512 digest mismatch")))
	})

	It("rejects an outright sha256 mismatch", func() {
		subj := map[string]string{"sha256": sha256Hex([]byte("other"))}
		Expect(attest.MatchSubjectDigests(data, subj, "sha256")).To(MatchError(ContainSubstring("sha256 digest mismatch")))
	})

	It("is unbindable (rejects) when no digest is polypkg-computable at/above the floor", func() {
		subj := map[string]string{"future-hash-3": "abcdef"}
		Expect(attest.MatchSubjectDigests(data, subj, "sha256")).To(MatchError(ContainSubstring("no digest at or above floor")))
	})

	It("ignores an unknown algorithm but still binds on a matching sha256", func() {
		subj := map[string]string{"sha256": sha256Hex(data), "future-hash-3": "whatever"}
		Expect(attest.MatchSubjectDigests(data, subj, "sha256")).To(Succeed())
	})

	It("rejects a subject offering a forbidden weak algorithm (sha1)", func() {
		subj := map[string]string{"sha1": "deadbeef", "sha256": sha256Hex(data)}
		Expect(attest.MatchSubjectDigests(data, subj, "sha256")).To(MatchError(ContainSubstring("forbidden weak digest")))
	})

	It("rejects a forbidden weak algorithm (md5) even alone", func() {
		Expect(attest.MatchSubjectDigests(data, map[string]string{"md5": "x"}, "sha256")).To(MatchError(ContainSubstring("forbidden weak digest")))
	})

	It("rejects an empty subject digest set", func() {
		Expect(attest.MatchSubjectDigests(data, map[string]string{}, "sha256")).To(MatchError(ContainSubstring("no digests")))
	})

	It("rejects an invalid floor", func() {
		Expect(attest.MatchSubjectDigests(data, map[string]string{"sha256": sha256Hex(data)}, "md5")).To(MatchError(ContainSubstring("invalid digest floor")))
	})
})

var _ = Describe("BindSubjects", func() {
	It("binds by digest, not by name (G5)", func() {
		body := []byte("hello world")
		subjects := []attest.Subject{{
			Name:   "wrong-name.txt", // name is advisory; binding is by digest (G5)
			Digest: map[string]string{"sha256": sha256Hex(body)},
		}}
		targets := []attest.Target{
			{Scope: "artifact", Bytes: []byte("other")},
			{Scope: "content:hello.txt", Bytes: body},
		}
		mats, err := attest.BindSubjects(subjects, targets)
		Expect(err).NotTo(HaveOccurred())
		Expect(mats).To(HaveLen(1))
		Expect(mats[0].Name).To(Equal("content:hello.txt"))
	})

	It("fails closed when nothing binds", func() {
		subjects := []attest.Subject{{
			Name:   "x",
			Digest: map[string]string{"sha256": sha256Hex([]byte("not present"))},
		}}
		targets := []attest.Target{{Scope: "artifact", Bytes: []byte("something else")}}
		_, err := attest.BindSubjects(subjects, targets)
		Expect(err).To(HaveOccurred())
	})

	It("rejects a target whose subject offers a forbidden weak digest", func() {
		// A subject offering md5 is rejected by MatchSubjectDigests, so it does NOT
		// bind even if a target's sha256 would match — the whole set fails closed.
		body := []byte("data")
		subjects := []attest.Subject{{
			Name:   "x",
			Digest: map[string]string{"sha256": sha256Hex(body), "md5": "00"},
		}}
		targets := []attest.Target{{Scope: "artifact", Bytes: body}}
		_, err := attest.BindSubjects(subjects, targets)
		Expect(err).To(HaveOccurred())
	})

	It("binds each subject once", func() {
		a, b := []byte("aaa"), []byte("bbb")
		subjects := []attest.Subject{
			{Name: "s1", Digest: map[string]string{"sha256": sha256Hex(a)}},
			{Name: "s2", Digest: map[string]string{"sha256": sha256Hex(b)}},
		}
		targets := []attest.Target{
			{Scope: "content:a", Bytes: a},
			{Scope: "content:b", Bytes: b},
		}
		mats, err := attest.BindSubjects(subjects, targets)
		Expect(err).NotTo(HaveOccurred())
		Expect(mats).To(HaveLen(2))
	})
})
