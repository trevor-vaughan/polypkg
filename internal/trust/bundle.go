package trust

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// Bundle is a verified, freshness-checked trust bundle: the builder keyring and
// sigstore roots a source's publisher vouches for. It is separate from the
// minisign role model (Keyring) — builder keys are not roles; they are queried
// by (key_id, timestamp).
type Bundle struct {
	keys  []schema.BuilderKey
	roots []schema.SigstoreRoot
}

// NewBundleForTesting constructs a Bundle directly from keys and roots, bypassing
// the anchor-signed-document load path. Test-only: it exists so out-of-package
// specs (the planner's install-time binding scenarios) can build a Bundle with
// known builder keys and sigstore roots without minting and signing a full trust
// document. Production code must never call it — a real Bundle always comes from
// LoadBundle, which enforces the signature, source, freshness, and serial checks.
func NewBundleForTesting(keys []schema.BuilderKey, roots []schema.SigstoreRoot) *Bundle {
	return &Bundle{keys: keys, roots: roots}
}

func (v *minisignVerifier) LoadBundle(doc []byte, sig string, lastSerial uint64, acceptUntil string) (bundle *Bundle, serial uint64, graced bool, err error) {
	if err := Verify(v.anchorPub, doc, sig); err != nil {
		return nil, 0, false, fmt.Errorf("trust bundle signature: %w", err)
	}
	b, err := schema.ParseTrustBundle(bytes.NewReader(doc))
	if err != nil {
		return nil, 0, false, fmt.Errorf("parse trust bundle: %w", err)
	}
	if b.Source != v.source {
		return nil, 0, false, fmt.Errorf("trust bundle is for source %q, expected %q", b.Source, v.source)
	}
	graced, err = CheckExpiry("trust bundle", b.Expires, acceptUntil)
	if err != nil {
		return nil, 0, false, err
	}
	if b.Serial < lastSerial {
		return nil, 0, false, fmt.Errorf("trust bundle rollback: serial %d is below last-seen %d", b.Serial, lastSerial)
	}
	return &Bundle{keys: b.BuilderKeys, roots: b.SigstoreRoots}, b.Serial, graced, nil
}

// BuilderKeyAt returns the builder key with the given id whose validity window
// [valid_from, valid_until] contains at (inclusive; absent valid_until is
// open-ended). Callers pass the attestation's build timestamp, never
// verification time. It distinguishes an unknown key id from a known key that
// is out of window, so callers and operators can tell "never trusted" from
// "trusted, but not when this artifact was built".
func (b *Bundle) BuilderKeyAt(keyID string, at time.Time) (schema.BuilderKey, error) {
	sawID := false
	for _, k := range b.keys {
		if k.KeyID != keyID {
			continue
		}
		sawID = true
		ok, err := within(k.ValidFrom, k.ValidUntil, at)
		if err != nil {
			return schema.BuilderKey{}, fmt.Errorf("builder key %q window: %w", keyID, err)
		}
		if ok {
			return k, nil
		}
	}
	if sawID {
		return schema.BuilderKey{}, fmt.Errorf("builder key %q not valid at %s", keyID, at.UTC().Format(time.RFC3339))
	}
	return schema.BuilderKey{}, fmt.Errorf("no builder key %q in trust bundle", keyID)
}

// BuilderKey returns the builder key registered under keyID ignoring its
// validity window, and whether one was found. Phase 2c-1a uses this for
// builder-signature verification (the DSSE signature is the security decision);
// the window gate — BuilderKeyAt keyed on the attestation's build timestamp —
// is applied by phase 2c-1b once that timestamp is parsed from the predicate.
// If several entries share a key id, the first wins; bundles SHOULD keep key ids
// unique (the keyring is append-only and rotation supersedes, not duplicates).
func (b *Bundle) BuilderKey(keyID string) (schema.BuilderKey, bool) {
	for _, k := range b.keys {
		if k.KeyID == keyID {
			return k, true
		}
	}
	return schema.BuilderKey{}, false
}

// SigstoreRootAt returns the mirrored sigstore root whose window contains at,
// and whether one was found. It delegates to SelectSigstoreRoot over this
// bundle's roots.
func (b *Bundle) SigstoreRootAt(at time.Time) (schema.SigstoreRoot, bool) {
	return SelectSigstoreRoot(b.roots, at)
}

// SelectSigstoreRoot returns the first root in roots whose window contains at,
// and whether one was found. A root whose window fails to parse is treated as
// absent (skipped), so a malformed root can only ever yield "no root found" —
// the caller, finding no usable root, fails closed. This has no error channel:
// the not-found result IS the fail-closed signal. It backs both the mirrored
// path (SigstoreRootAt) and the consumer-pinned path (planner 2e-5), so the two
// share one window implementation.
func SelectSigstoreRoot(roots []schema.SigstoreRoot, at time.Time) (schema.SigstoreRoot, bool) {
	for _, r := range roots {
		ok, err := within(r.ValidFrom, r.ValidUntil, at)
		if err == nil && ok {
			return r, true
		}
	}
	return schema.SigstoreRoot{}, false
}

// within reports whether at falls in [from, until] (inclusive). from is
// required; an empty until is treated as open-ended. Timestamps are RFC3339.
// The document is schema-validated as date-time, but Go's time.RFC3339 layout
// is stricter than RFC 3339 (it rejects the lowercase t/z and space-separator
// forms the JSON-Schema format checker accepts), so a parse failure here is
// genuinely reachable — it fails closed (surfaces an error, never a silent
// match). Do not remove this guard as unreachable.
func within(from, until string, at time.Time) (bool, error) {
	f, err := time.Parse(time.RFC3339, from)
	if err != nil {
		return false, fmt.Errorf("valid_from %q: %w", from, err)
	}
	if at.Before(f) {
		return false, nil
	}
	if until == "" {
		return true, nil
	}
	u, err := time.Parse(time.RFC3339, until)
	if err != nil {
		return false, fmt.Errorf("valid_until %q: %w", until, err)
	}
	return !at.After(u), nil
}

// Revocations is a verified, freshness-checked revocation list: the builder
// keys and attestation content-hashes a source's publisher has revoked.
type Revocations struct {
	keys map[string]struct{}
	atts map[string]struct{}
}

func (v *minisignVerifier) LoadRevocationList(doc []byte, sig string, lastSerial uint64, acceptUntil string) (revocations *Revocations, serial uint64, graced bool, expires string, err error) {
	if err := Verify(v.anchorPub, doc, sig); err != nil {
		return nil, 0, false, "", fmt.Errorf("revocation list signature: %w", err)
	}
	rl, err := schema.ParseRevocationList(bytes.NewReader(doc))
	if err != nil {
		return nil, 0, false, "", fmt.Errorf("parse revocation list: %w", err)
	}
	if rl.Source != v.source {
		return nil, 0, false, "", fmt.Errorf("revocation list is for source %q, expected %q", rl.Source, v.source)
	}
	graced, err = CheckExpiry("revocation list", rl.Expires, acceptUntil)
	if err != nil {
		return nil, 0, false, "", err
	}
	if rl.Serial < lastSerial {
		return nil, 0, false, "", fmt.Errorf("revocation list rollback: serial %d is below last-seen %d", rl.Serial, lastSerial)
	}
	r := &Revocations{keys: map[string]struct{}{}, atts: map[string]struct{}{}}
	for _, k := range rl.RevokedBuilderKeys {
		r.keys[k] = struct{}{}
	}
	for _, a := range rl.RevokedAttestations {
		r.atts[a] = struct{}{}
	}
	return r, rl.Serial, graced, rl.Expires, nil
}

// IsBuilderKeyRevoked reports whether the given builder key_id is revoked.
func (r *Revocations) IsBuilderKeyRevoked(keyID string) bool {
	_, ok := r.keys[keyID]
	return ok
}

// IsAttestationRevoked reports whether the given attestation blake3 content-hash
// is revoked.
func (r *Revocations) IsAttestationRevoked(contentHash string) bool {
	_, ok := r.atts[contentHash]
	return ok
}

// RevokedBuilderKeyIDs returns the revoked builder key IDs in sorted order.
// Nil-safe: a nil receiver (no revocation list fetched) returns nil.
func (r *Revocations) RevokedBuilderKeyIDs() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.keys))
	for k := range r.keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
