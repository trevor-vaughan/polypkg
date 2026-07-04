package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// tkey is a test minisign keypair built on stdlib ed25519.
type tkey struct {
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	keyID [8]byte
}

func newTKey() tkey {
	GinkgoHelper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	var id [8]byte
	_, err = rand.Read(id[:])
	Expect(err).NotTo(HaveOccurred())
	return tkey{pub: pub, priv: priv, keyID: id}
}

func (k tkey) pubFile() string {
	bin := append([]byte{'E', 'd'}, k.keyID[:]...)
	bin = append(bin, k.pub...)
	return "untrusted comment: t\n" + base64.StdEncoding.EncodeToString(bin) + "\n"
}

func (k tkey) pubB64() string {
	bin := append([]byte{'E', 'd'}, k.keyID[:]...)
	bin = append(bin, k.pub...)
	return base64.StdEncoding.EncodeToString(bin)
}

func (k tkey) idHex() string { return hex.EncodeToString(k.keyID[:]) }

func (k tkey) sign(data []byte, comment string) string {
	sig := ed25519.Sign(k.priv, data)
	sigBin := append([]byte{'E', 'd'}, k.keyID[:]...)
	sigBin = append(sigBin, sig...)
	global := ed25519.Sign(k.priv, append(append([]byte{}, sig...), []byte(comment)...))
	return "untrusted comment: t\n" + base64.StdEncoding.EncodeToString(sigBin) + "\n" +
		"trusted comment: " + comment + "\n" + base64.StdEncoding.EncodeToString(global) + "\n"
}

func trustDocJSON(anchor tkey, source string, serial uint64, keys []schema.TrustKey, revoked []string) (doc []byte, sig string) {
	GinkgoHelper()
	td := schema.TrustDoc{Schema: "polypkg.trust/v2", Source: source, Serial: serial, Expires: "2099-01-01T00:00:00Z", Keys: keys, Revoked: revoked}
	raw, err := json.Marshal(td)
	Expect(err).NotTo(HaveOccurred())
	return raw, anchor.sign(raw, "timestamp:0")
}

var _ = Describe("LoadTrust", func() {
	It("happy path: verifies anchor sig, returns serial, and the resulting state verifies an index sig with claims", func() {
		anchor := newTKey()
		idx := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, sig := trustDocJSON(anchor, "native", 3,
			[]schema.TrustKey{{ID: idx.idHex(), Pubkey: idx.pubB64(), Roles: []string{"index"}}}, nil)
		state, serial, err := v.LoadTrust(doc, sig, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(serial).To(Equal(uint64(3)))

		data := []byte("the index bytes")
		claims, err := state.Verify(RoleIndex, data, idx.sign(data, "serial=9 ts=2026-01-01T00:00:00Z"))
		Expect(err).NotTo(HaveOccurred())
		n, err := claims.IndexSerial()
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(uint64(9)))
		Expect(claims.KeyID).To(Equal(idx.idHex()))
	})

	It("accepts serial equal to the last-seen serial", func() {
		anchor := newTKey()
		idx := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		good := []schema.TrustKey{{ID: idx.idHex(), Pubkey: idx.pubB64(), Roles: []string{"index"}}}
		doc, sig := trustDocJSON(anchor, "native", 6, good, nil)
		_, serial, err := v.LoadTrust(doc, sig, 6)
		Expect(err).NotTo(HaveOccurred())
		Expect(serial).To(Equal(uint64(6)))
	})

	It("rejects a trust document past its expires BEFORE the serial check (a stale doc must not advance anything)", func() {
		anchor := newTKey()
		idx := newTKey()
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		td := schema.TrustDoc{
			Schema:  "polypkg.trust/v2",
			Source:  "native",
			Serial:  1,
			Expires: "2020-01-01T00:00:00Z",
			Keys:    []schema.TrustKey{{ID: idx.idHex(), Pubkey: idx.pubB64(), Roles: []string{"index"}}},
		}
		raw, err := json.Marshal(td)
		Expect(err).NotTo(HaveOccurred())
		sig := anchor.sign(raw, "timestamp:0")

		// lastSerial 6 would also be a rollback (serial 1 < 6): the error must
		// name staleness, proving expiry is enforced before serial logic runs.
		_, _, err = v.LoadTrust(raw, sig, 6)
		Expect(err).To(MatchError(ContainSubstring("trust document expired at")))
		Expect(err).To(MatchError(ContainSubstring("stale metadata refused")))
		Expect(err.Error()).NotTo(ContainSubstring("rollback"))
	})

	It("types the source mismatch so callers can attach a recovery hint", func() {
		// Same fixture shape as the "source mismatch" table entry below; this
		// spec additionally pins the typed error and its fields.
		anchor := newTKey()
		idx := newTKey()
		good := []schema.TrustKey{{ID: idx.idHex(), Pubkey: idx.pubB64(), Roles: []string{"index"}}}
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, sig := trustDocJSON(anchor, "other", 1, good, nil)
		_, _, err = v.LoadTrust(doc, sig, 0)
		Expect(err).To(MatchError(ContainSubstring(`trust document is for source "other", expected "native"`)))
		var mm *SourceNameMismatchError
		Expect(errors.As(err, &mm)).To(BeTrue(), "expected *SourceNameMismatchError, got %T: %v", err, err)
		Expect(mm.Doc).To(Equal("other"))
		Expect(mm.Expected).To(Equal("native"))
	})

	DescribeTable("rejects",
		// build is a closure so each Entry can create fresh keys; the table
		// supplies the rejection setup logic and the expected error substring
		// (empty string means "any error").
		func(build func() (v Verifier, doc []byte, sig string, lastSerial uint64), wantSubstr string) {
			v, doc, sig, lastSerial := build()
			_, _, err := v.LoadTrust(doc, sig, lastSerial)
			Expect(err).To(HaveOccurred())
			if wantSubstr != "" {
				Expect(err.Error()).To(ContainSubstring(wantSubstr))
			}
		},
		Entry("wrong anchor signature",
			func() (Verifier, []byte, string, uint64) {
				anchor := newTKey()
				other := newTKey()
				idx := newTKey()
				good := []schema.TrustKey{{ID: idx.idHex(), Pubkey: idx.pubB64(), Roles: []string{"index"}}}
				v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
				Expect(err).NotTo(HaveOccurred())
				doc, _ := trustDocJSON(anchor, "native", 1, good, nil)
				_, badSig := trustDocJSON(other, "native", 1, good, nil)
				return v, doc, badSig, 0
			},
			"",
		),
		Entry("source mismatch",
			func() (Verifier, []byte, string, uint64) {
				anchor := newTKey()
				idx := newTKey()
				good := []schema.TrustKey{{ID: idx.idHex(), Pubkey: idx.pubB64(), Roles: []string{"index"}}}
				v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
				Expect(err).NotTo(HaveOccurred())
				doc, sig := trustDocJSON(anchor, "other", 1, good, nil)
				return v, doc, sig, 0
			},
			"source",
		),
		Entry("serial rollback",
			func() (Verifier, []byte, string, uint64) {
				anchor := newTKey()
				idx := newTKey()
				good := []schema.TrustKey{{ID: idx.idHex(), Pubkey: idx.pubB64(), Roles: []string{"index"}}}
				v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
				Expect(err).NotTo(HaveOccurred())
				doc, sig := trustDocJSON(anchor, "native", 5, good, nil)
				return v, doc, sig, 6
			},
			"rollback",
		),
		Entry("id does not match pubkey",
			func() (Verifier, []byte, string, uint64) {
				anchor := newTKey()
				other := newTKey()
				idx := newTKey()
				v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
				Expect(err).NotTo(HaveOccurred())
				bad := []schema.TrustKey{{ID: other.idHex(), Pubkey: idx.pubB64(), Roles: []string{"index"}}}
				doc, sig := trustDocJSON(anchor, "native", 1, bad, nil)
				return v, doc, sig, 0
			},
			"does not match",
		),
		Entry("key in both keys and revoked",
			func() (Verifier, []byte, string, uint64) {
				anchor := newTKey()
				idx := newTKey()
				good := []schema.TrustKey{{ID: idx.idHex(), Pubkey: idx.pubB64(), Roles: []string{"index"}}}
				v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
				Expect(err).NotTo(HaveOccurred())
				doc, sig := trustDocJSON(anchor, "native", 1, good, []string{idx.idHex()})
				return v, doc, sig, 0
			},
			"both",
		),
		Entry("duplicate key (invariant enforced in newMinisignState, not schema)",
			func() (Verifier, []byte, string, uint64) {
				anchor := newTKey()
				idx := newTKey()
				v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
				Expect(err).NotTo(HaveOccurred())
				dup := []schema.TrustKey{
					{ID: idx.idHex(), Pubkey: idx.pubB64(), Roles: []string{"index"}},
					{ID: idx.idHex(), Pubkey: idx.pubB64(), Roles: []string{"artifact"}},
				}
				doc, sig := trustDocJSON(anchor, "native", 1, dup, nil)
				return v, doc, sig, 0
			},
			"duplicate",
		),
	)
})

var _ = Describe("TrustState.Verify policy", func() {
	// Each Entry rebuilds the full key set: keeping construction inside the
	// closure preserves test isolation while exercising the same Verify path.
	type policyCase struct {
		role        Role
		dataToSign  []byte // payload signed under the chosen key
		dataToCheck []byte // payload passed to Verify (differs only in "bad crypto")
		comment     string
		signWith    func(art, idx, revoked tkey) tkey
		wantSubstr  string // empty means "any error"
		wantOK      bool
		check       func(claims Claims)
	}

	run := func(c policyCase) {
		anchor := newTKey()
		idx := newTKey()
		art := newTKey()
		revoked := newTKey()
		keys := []schema.TrustKey{
			{ID: idx.idHex(), Pubkey: idx.pubB64(), Roles: []string{"index"}},
			{ID: art.idHex(), Pubkey: art.pubB64(), Roles: []string{"artifact"}},
		}
		v, err := NewVerifier("polypkg-native", anchor.pubFile(), "native")
		Expect(err).NotTo(HaveOccurred())
		doc, sig := trustDocJSON(anchor, "native", 1, keys, []string{revoked.idHex()})
		state, _, err := v.LoadTrust(doc, sig, 0)
		Expect(err).NotTo(HaveOccurred())

		signer := c.signWith(art, idx, revoked)
		signed := signer.sign(c.dataToSign, c.comment)
		claims, err := state.Verify(c.role, c.dataToCheck, signed)
		if c.wantOK {
			Expect(err).NotTo(HaveOccurred())
			if c.check != nil {
				c.check(claims)
			}
			return
		}
		Expect(err).To(HaveOccurred())
		if c.wantSubstr != "" {
			Expect(err.Error()).To(ContainSubstring(c.wantSubstr))
		}
	}

	data := []byte("payload")

	DescribeTable("policy",
		run,
		Entry("role mismatch (artifact key under index role)",
			policyCase{
				role:        RoleIndex,
				dataToSign:  data,
				dataToCheck: data,
				comment:     "x=1",
				signWith:    func(art, _, _ tkey) tkey { return art },
				wantSubstr:  "role",
			},
		),
		Entry("unknown key",
			policyCase{
				role:        RoleArtifact,
				dataToSign:  data,
				dataToCheck: data,
				comment:     "x=1",
				// Build a fresh key inside the closure — it is not in the trust set.
				signWith:   func(_, _, _ tkey) tkey { return newTKey() },
				wantSubstr: "not in the trust set",
			},
		),
		Entry("revoked key",
			policyCase{
				role:        RoleArtifact,
				dataToSign:  data,
				dataToCheck: data,
				comment:     "x=1",
				signWith:    func(_, _, revoked tkey) tkey { return revoked },
				wantSubstr:  "revoked",
			},
		),
		Entry("bad crypto (signed payload differs from verified payload)",
			policyCase{
				role:        RoleArtifact,
				dataToSign:  data,
				dataToCheck: []byte("tampered"),
				comment:     "name=a version=1 hash=blake3:x",
				signWith:    func(art, _, _ tkey) tkey { return art },
				wantSubstr:  "",
			},
		),
		Entry("artifact claims surface name/version/hash",
			policyCase{
				role:        RoleArtifact,
				dataToSign:  data,
				dataToCheck: data,
				comment:     "name=hello version=1.0.0 hash=blake3:abc",
				signWith:    func(art, _, _ tkey) tkey { return art },
				wantOK:      true,
				check: func(claims Claims) {
					n, vv, h, err := claims.Artifact()
					Expect(err).NotTo(HaveOccurred())
					Expect(n).To(Equal("hello"))
					Expect(vv).To(Equal("1.0.0"))
					Expect(h).To(Equal("blake3:abc"))
				},
			},
		),
	)
})
