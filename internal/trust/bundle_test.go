package trust

import (
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// bundleJSON marshals a bundle and anchor-signs it (mirrors trustDocJSON).
func bundleJSON(anchor tkey, source string, serial uint64, expires string, keys []schema.BuilderKey, roots []schema.SigstoreRoot) (doc []byte, sig string) {
	GinkgoHelper()
	b := schema.TrustBundle{
		Schema:        "polypkg.trust-bundle/v1",
		Source:        source,
		Serial:        serial,
		Expires:       expires,
		BuilderKeys:   keys,
		SigstoreRoots: roots,
	}
	raw, err := json.Marshal(b)
	Expect(err).NotTo(HaveOccurred())
	return raw, anchor.sign(raw, "serial=0")
}

func mustParse(ts string) time.Time {
	GinkgoHelper()
	t, err := time.Parse(time.RFC3339, ts)
	Expect(err).NotTo(HaveOccurred())
	return t
}

var _ = Describe("LoadBundle", func() {
	windowedKey := []schema.BuilderKey{{
		KeyID:      "builder-a",
		PublicKey:  "cHVia2V5",
		Algo:       "ed25519",
		ValidFrom:  "2026-01-01T00:00:00Z",
		ValidUntil: "2027-01-01T00:00:00Z",
	}}

	It("happy path: verifies anchor sig, returns serial, and finds an in-window builder key", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, sig := bundleJSON(anchor, "native", 5, "2099-01-01T00:00:00Z", windowedKey, nil)
		b, serial, _, err := v.LoadBundle(doc, sig, 0, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(serial).To(Equal(uint64(5)))

		key, err := b.BuilderKeyAt("builder-a", mustParse("2026-06-01T00:00:00Z"))
		Expect(err).NotTo(HaveOccurred())
		Expect(key.PublicKey).To(Equal("cHVia2V5"))
	})

	It("accepts serial equal to the last-seen serial", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, sig := bundleJSON(anchor, "native", 6, "2099-01-01T00:00:00Z", nil, nil)
		_, serial, _, err := v.LoadBundle(doc, sig, 6, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(serial).To(Equal(uint64(6)))
	})

	It("rejects a bad anchor signature", func() {
		anchor := newTKey()
		other := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, _ := bundleJSON(anchor, "native", 1, "2099-01-01T00:00:00Z", nil, nil)
		_, wrongSig := bundleJSON(other, "native", 1, "2099-01-01T00:00:00Z", nil, nil)
		_, _, _, err = v.LoadBundle(doc, wrongSig, 0, "")
		Expect(err).To(MatchError(ContainSubstring("trust bundle signature")))
	})

	It("rejects a bundle bound to a different source", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, sig := bundleJSON(anchor, "other", 1, "2099-01-01T00:00:00Z", nil, nil)
		_, _, _, err = v.LoadBundle(doc, sig, 0, "")
		Expect(err).To(MatchError(ContainSubstring(`trust bundle is for source "other", expected "native"`)))
	})

	It("rejects a bundle past its expires BEFORE the serial check", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		// serial 1 with lastSerial 6 would also be a rollback; the error must
		// name staleness, proving expiry is enforced first.
		doc, sig := bundleJSON(anchor, "native", 1, "2020-01-01T00:00:00Z", nil, nil)
		_, _, _, err = v.LoadBundle(doc, sig, 6, "")
		Expect(err).To(MatchError(ContainSubstring("trust bundle expired at")))
		Expect(err).To(MatchError(ContainSubstring("stale metadata refused")))
		Expect(err.Error()).NotTo(ContainSubstring("rollback"))
	})

	It("rejects a rolled-back serial", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, sig := bundleJSON(anchor, "native", 2, "2099-01-01T00:00:00Z", nil, nil)
		_, _, _, err = v.LoadBundle(doc, sig, 5, "")
		Expect(err).To(MatchError(ContainSubstring("trust bundle rollback: serial 2 is below last-seen 5")))
	})

	It("grants grace and reports graced=true for an expired bundle within accept_expiry_until", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, sig := bundleJSON(anchor, "native", 3, "2020-01-01T00:00:00Z", nil, nil)
		accept := timeNow().Add(24 * time.Hour).UTC().Format(time.RFC3339)
		_, serial, graced, err := v.LoadBundle(doc, sig, 0, accept)
		Expect(err).NotTo(HaveOccurred())
		Expect(serial).To(Equal(uint64(3)))
		Expect(graced).To(BeTrue())
	})

	It("grace does NOT bypass the serial rollback floor", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		// Validly-signed, EXPIRED bundle at serial 1; lastSerial 5 means grace
		// must not admit it as a rollback.
		doc, sig := bundleJSON(anchor, "native", 1, "2020-01-01T00:00:00Z", nil, nil)
		accept := timeNow().Add(24 * time.Hour).UTC().Format(time.RFC3339)
		_, _, graced, err := v.LoadBundle(doc, sig, 5, accept)
		Expect(err).To(MatchError(ContainSubstring("rollback")))
		Expect(graced).To(BeFalse())
	})

	It("rejects a trust bundle with serial 0 (serial 0 is reserved for never-seen)", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, sig := bundleJSON(anchor, "native", 0, "2099-01-01T00:00:00Z", nil, nil)
		_, _, _, err = v.LoadBundle(doc, sig, 0, "")
		Expect(err).To(HaveOccurred())
	})

	Describe("BuilderKeyAt", func() {
		load := func(keys []schema.BuilderKey) *Bundle {
			GinkgoHelper()
			anchor := newTKey()
			v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
			Expect(err).NotTo(HaveOccurred())
			doc, sig := bundleJSON(anchor, "native", 1, "2099-01-01T00:00:00Z", keys, nil)
			b, _, _, err := v.LoadBundle(doc, sig, 0, "")
			Expect(err).NotTo(HaveOccurred())
			return b
		}

		It("rejects a timestamp before the window", func() {
			b := load(windowedKey)
			_, err := b.BuilderKeyAt("builder-a", mustParse("2025-06-01T00:00:00Z"))
			Expect(err).To(MatchError(ContainSubstring("not valid at")))
		})

		It("rejects a timestamp after the window", func() {
			b := load(windowedKey)
			_, err := b.BuilderKeyAt("builder-a", mustParse("2028-06-01T00:00:00Z"))
			Expect(err).To(MatchError(ContainSubstring("not valid at")))
		})

		It("treats absent valid_until as open-ended", func() {
			openKey := []schema.BuilderKey{{
				KeyID: "builder-a", PublicKey: "cHVia2V5", Algo: "ed25519",
				ValidFrom: "2026-01-01T00:00:00Z",
			}}
			b := load(openKey)
			_, err := b.BuilderKeyAt("builder-a", mustParse("2099-06-01T00:00:00Z"))
			Expect(err).NotTo(HaveOccurred())
		})

		It("rejects an unknown key id distinctly from an out-of-window key", func() {
			b := load(windowedKey)
			_, err := b.BuilderKeyAt("builder-z", mustParse("2026-06-01T00:00:00Z"))
			Expect(err).To(MatchError(ContainSubstring("no builder key")))
		})

		It("fails closed (wrapped window error) when a matching key's timestamp is unparseable by Go's stricter RFC3339", func() {
			// RFC 3339 permits a lowercase 't'/'z'; the JSON-Schema date-time
			// checker accepts those, but Go's time.RFC3339 layout rejects them.
			// The window guard is therefore reachable in production and must
			// surface as an error, never a silent match. Construct the Bundle
			// directly (in-package) to exercise that branch hermetically,
			// independent of how leniently the schema validator treats it.
			b := &Bundle{keys: []schema.BuilderKey{{
				KeyID: "builder-a", PublicKey: "cHVia2V5", Algo: "ed25519",
				ValidFrom: "2026-01-01t00:00:00Z",
			}}}
			_, err := b.BuilderKeyAt("builder-a", mustParse("2026-06-01T00:00:00Z"))
			Expect(err).To(MatchError(ContainSubstring("window")))
		})
	})

	Describe("BuilderKey (window-agnostic)", func() {
		load := func(keys []schema.BuilderKey) *Bundle {
			GinkgoHelper()
			anchor := newTKey()
			v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
			Expect(err).NotTo(HaveOccurred())
			doc, sig := bundleJSON(anchor, "native", 1, "2099-01-01T00:00:00Z", keys, nil)
			b, _, _, err := v.LoadBundle(doc, sig, 0, "")
			Expect(err).NotTo(HaveOccurred())
			return b
		}

		It("returns a known key ignoring its validity window", func() {
			// windowedKey's window is 2026..2027; BuilderKey ignores it entirely.
			b := load(windowedKey)
			k, ok := b.BuilderKey("builder-a")
			Expect(ok).To(BeTrue())
			Expect(k.PublicKey).To(Equal("cHVia2V5"))
		})

		It("reports not-found for an unknown key id", func() {
			b := load(windowedKey)
			_, ok := b.BuilderKey("builder-z")
			Expect(ok).To(BeFalse())
		})
	})

	Describe("SigstoreRootAt", func() {
		roots := []schema.SigstoreRoot{{
			ValidFrom:  "2026-01-01T00:00:00Z",
			ValidUntil: "2027-01-01T00:00:00Z",
			FulcioCA:   []string{"ZnVsY2lv"},
			RekorKeys:  []string{"cmVrb3I="},
		}}

		load := func() *Bundle {
			GinkgoHelper()
			anchor := newTKey()
			v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
			Expect(err).NotTo(HaveOccurred())
			doc, sig := bundleJSON(anchor, "native", 1, "2099-01-01T00:00:00Z", nil, roots)
			b, _, _, err := v.LoadBundle(doc, sig, 0, "")
			Expect(err).NotTo(HaveOccurred())
			return b
		}

		It("returns the roots valid at the given time", func() {
			b := load()
			r, ok := b.SigstoreRootAt(mustParse("2026-06-01T00:00:00Z"))
			Expect(ok).To(BeTrue())
			Expect(r.FulcioCA).To(Equal([]string{"ZnVsY2lv"}))
		})

		It("returns false when no roots cover the given time", func() {
			b := load()
			_, ok := b.SigstoreRootAt(mustParse("2030-06-01T00:00:00Z"))
			Expect(ok).To(BeFalse())
		})
	})
})

var _ = Describe("SelectSigstoreRoot", func() {
	mkRoot := func(from, until string) schema.SigstoreRoot {
		return schema.SigstoreRoot{ValidFrom: from, ValidUntil: until, FulcioCA: []string{"ca"}, RekorKeys: []string{"rk"}}
	}

	It("returns the first root whose window contains the instant", func() {
		roots := []schema.SigstoreRoot{
			mkRoot("2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z"),
			mkRoot("2024-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
		}
		r, ok := SelectSigstoreRoot(roots, mustParse("2025-06-01T00:00:00Z"))
		Expect(ok).To(BeTrue())
		Expect(r.ValidFrom).To(Equal("2024-01-01T00:00:00Z"))
	})

	It("returns not-found when the instant is outside every window", func() {
		roots := []schema.SigstoreRoot{mkRoot("2024-01-01T00:00:00Z", "2026-01-01T00:00:00Z")}
		_, ok := SelectSigstoreRoot(roots, mustParse("2000-01-01T00:00:00Z"))
		Expect(ok).To(BeFalse())
	})

	It("skips a root whose window fails to parse (fail closed)", func() {
		roots := []schema.SigstoreRoot{mkRoot("not-a-timestamp", "")}
		_, ok := SelectSigstoreRoot(roots, mustParse("2025-06-01T00:00:00Z"))
		Expect(ok).To(BeFalse())
	})

	It("treats an empty valid_until as open-ended", func() {
		roots := []schema.SigstoreRoot{mkRoot("2024-01-01T00:00:00Z", "")}
		r, ok := SelectSigstoreRoot(roots, mustParse("2099-01-01T00:00:00Z"))
		Expect(ok).To(BeTrue())
		Expect(r.ValidFrom).To(Equal("2024-01-01T00:00:00Z"))
	})
})

var _ = Describe("LoadRevocationList", func() {
	revJSON := func(anchor tkey, source string, serial uint64, expires string, keys, atts []string) (doc []byte, sig string) {
		GinkgoHelper()
		rl := schema.RevocationList{
			Schema: "polypkg.revocation-list/v1", Source: source, Serial: serial,
			Expires: expires, RevokedBuilderKeys: keys, RevokedAttestations: atts,
		}
		raw, err := json.Marshal(rl)
		Expect(err).NotTo(HaveOccurred())
		return raw, anchor.sign(raw, "serial=0")
	}

	It("happy path: verifies, returns serial, and answers revocation queries", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, sig := revJSON(anchor, "native", 3, "2099-01-01T00:00:00Z",
			[]string{"builder-a"}, []string{"blake3:deadbeef"})
		r, serial, _, err := v.LoadRevocationList(doc, sig, 0, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(serial).To(Equal(uint64(3)))
		Expect(r.IsBuilderKeyRevoked("builder-a")).To(BeTrue())
		Expect(r.IsBuilderKeyRevoked("builder-b")).To(BeFalse())
		Expect(r.IsAttestationRevoked("blake3:deadbeef")).To(BeTrue())
		Expect(r.IsAttestationRevoked("blake3:cafe")).To(BeFalse())
	})

	It("rejects a bad anchor signature", func() {
		anchor := newTKey()
		other := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, _ := revJSON(anchor, "native", 1, "2099-01-01T00:00:00Z", nil, nil)
		_, wrongSig := revJSON(other, "native", 1, "2099-01-01T00:00:00Z", nil, nil)
		_, _, _, err = v.LoadRevocationList(doc, wrongSig, 0, "")
		Expect(err).To(MatchError(ContainSubstring("revocation list signature")))
	})

	It("rejects a list bound to a different source", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, sig := revJSON(anchor, "other", 1, "2099-01-01T00:00:00Z", nil, nil)
		_, _, _, err = v.LoadRevocationList(doc, sig, 0, "")
		Expect(err).To(MatchError(ContainSubstring(`revocation list is for source "other", expected "native"`)))
	})

	It("rejects a list past its expires BEFORE the serial check", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, sig := revJSON(anchor, "native", 1, "2020-01-01T00:00:00Z", nil, nil)
		_, _, _, err = v.LoadRevocationList(doc, sig, 6, "")
		Expect(err).To(MatchError(ContainSubstring("revocation list expired at")))
		Expect(err.Error()).NotTo(ContainSubstring("rollback"))
	})

	It("rejects a rolled-back serial", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, sig := revJSON(anchor, "native", 2, "2099-01-01T00:00:00Z", nil, nil)
		_, _, _, err = v.LoadRevocationList(doc, sig, 5, "")
		Expect(err).To(MatchError(ContainSubstring("revocation list rollback: serial 2 is below last-seen 5")))
	})

	It("grants grace and reports graced=true for an expired revocation list within accept_expiry_until", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, sig := revJSON(anchor, "native", 3, "2020-01-01T00:00:00Z", nil, nil)
		accept := timeNow().Add(24 * time.Hour).UTC().Format(time.RFC3339)
		_, serial, graced, err := v.LoadRevocationList(doc, sig, 0, accept)
		Expect(err).NotTo(HaveOccurred())
		Expect(serial).To(Equal(uint64(3)))
		Expect(graced).To(BeTrue())
	})

	It("grace does NOT bypass the serial rollback floor", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		// Validly-signed, EXPIRED revocation list at serial 1; lastSerial 5 means
		// grace must not admit it as a rollback.
		doc, sig := revJSON(anchor, "native", 1, "2020-01-01T00:00:00Z", nil, nil)
		accept := timeNow().Add(24 * time.Hour).UTC().Format(time.RFC3339)
		_, _, graced, err := v.LoadRevocationList(doc, sig, 5, accept)
		Expect(err).To(MatchError(ContainSubstring("rollback")))
		Expect(graced).To(BeFalse())
	})

	It("rejects a revocation list with serial 0 (serial 0 is reserved for never-seen)", func() {
		anchor := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, sig := revJSON(anchor, "native", 0, "2099-01-01T00:00:00Z", nil, nil)
		_, _, _, err = v.LoadRevocationList(doc, sig, 0, "")
		Expect(err).To(HaveOccurred())
	})
})
