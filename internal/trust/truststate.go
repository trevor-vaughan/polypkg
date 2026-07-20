package trust

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/jedisct1/go-minisign"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

type minisignVerifier struct {
	anchorPub string
	source    string
}

// SourceNameMismatchError reports a trust document whose bound source name
// differs from the profile's source name. It is typed so the CLI can attach
// a recovery hint: the fix is a profile edit (or re-init), not a trust issue.
type SourceNameMismatchError struct {
	Doc      string // source name the signed trust document is bound to
	Expected string // source name the profile asked to verify
}

func (e *SourceNameMismatchError) Error() string {
	return fmt.Sprintf("trust document is for source %q, expected %q", e.Doc, e.Expected)
}

func (v *minisignVerifier) LoadTrust(doc []byte, sig string, lastTrustSerial uint64, acceptUntil string) (keyring Keyring, serial uint64, graced bool, err error) {
	if err := Verify(v.anchorPub, doc, sig); err != nil {
		return nil, 0, false, fmt.Errorf("trust document signature: %w", err)
	}
	td, err := schema.ParseTrustDoc(bytes.NewReader(doc))
	if err != nil {
		return nil, 0, false, fmt.Errorf("parse trust document: %w", err)
	}
	if td.Source != v.source {
		return nil, 0, false, &SourceNameMismatchError{Doc: td.Source, Expected: v.source}
	}
	// Freshness (with grace) before serial logic: a stale document must not
	// advance (or be compared against) the serial high-water mark (D13) — but
	// grace relaxes only the WALL-CLOCK bound; the rollback check below still
	// refuses a lower serial (spec §10.9 E-3).
	graced, err = CheckExpiry("trust document", td.Expires, acceptUntil)
	if err != nil {
		return nil, 0, false, err
	}
	if td.Serial < lastTrustSerial {
		return nil, 0, false, fmt.Errorf("trust document rollback: serial %d is below last-seen %d", td.Serial, lastTrustSerial)
	}
	st, err := newMinisignState(td)
	if err != nil {
		return nil, 0, false, err
	}
	return st, td.Serial, graced, nil
}

type minisignKey struct {
	pk    minisign.PublicKey
	roles map[Role]bool
}

type minisignState struct {
	keys    map[[8]byte]minisignKey
	revoked map[[8]byte]bool
}

func newMinisignState(td *schema.TrustDoc) (*minisignState, error) {
	st := &minisignState{keys: map[[8]byte]minisignKey{}, revoked: map[[8]byte]bool{}}
	for _, r := range td.Revoked {
		id, err := decodeKeyID(r)
		if err != nil {
			return nil, fmt.Errorf("revoked key id %q: %w", r, err)
		}
		st.revoked[id] = true
	}
	for _, k := range td.Keys {
		declared, err := decodeKeyID(k.ID)
		if err != nil {
			return nil, fmt.Errorf("key id %q: %w", k.ID, err)
		}
		pk, err := minisign.NewPublicKey(k.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("key %s: parse pubkey: %w", k.ID, err)
		}
		if pk.KeyId != declared {
			return nil, fmt.Errorf("key %s: id does not match pubkey (%x)", k.ID, pk.KeyId)
		}
		if st.revoked[declared] {
			return nil, fmt.Errorf("key %s appears in both keys and revoked", k.ID)
		}
		if _, dup := st.keys[declared]; dup {
			return nil, fmt.Errorf("duplicate key %s", k.ID)
		}
		roles := map[Role]bool{}
		for _, r := range k.Roles {
			roles[Role(r)] = true
		}
		st.keys[declared] = minisignKey{pk: pk, roles: roles}
	}
	return st, nil
}

func (s *minisignState) Verify(role Role, data []byte, sig string) (Claims, error) {
	id, err := sigKeyID(sig)
	if err != nil {
		return Claims{}, err
	}
	if s.revoked[id] {
		return Claims{}, fmt.Errorf("signing key %x is revoked", id)
	}
	key, ok := s.keys[id]
	if !ok {
		return Claims{}, fmt.Errorf("signing key %x is not in the trust set", id)
	}
	if !key.roles[role] {
		return Claims{}, fmt.Errorf("signing key %x is not authorised for role %q", id, role)
	}
	comment, err := verifyParsed(key.pk, data, sig)
	if err != nil {
		return Claims{}, err
	}
	values, err := parseComment(comment)
	if err != nil {
		return Claims{}, err
	}
	return Claims{KeyID: hex.EncodeToString(id[:]), Role: role, Values: values}, nil
}

// decodeKeyID parses a 16-hex-char minisign KeyId.
func decodeKeyID(s string) ([8]byte, error) {
	var id [8]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("not hex: %w", err)
	}
	if len(b) != 8 {
		return id, fmt.Errorf("expected 8 bytes, got %d", len(b))
	}
	copy(id[:], b)
	return id, nil
}
