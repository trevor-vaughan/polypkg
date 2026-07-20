package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// KeyLookup returns the ed25519 public key a trust bundle registers under keyID,
// or ok=false when the bundle has no usable key of that id. The planner adapts
// trust.Bundle.BuilderKey here (base64-decoding the stored key and rejecting a
// non-ed25519 algo or wrong-length key), which keeps this package free of a
// dependency on internal/trust.
type KeyLookup func(keyID string) (pub ed25519.PublicKey, ok bool)

// BuilderSigTier is the outcome of builder-signature verification, mapped by the
// caller to a schema.CarriedBinding tier.
type BuilderSigTier int

const (
	// BuilderSigNotDSSE means the envelope is a bare in-toto Statement, not a
	// DSSE envelope: there is no builder signature to verify. Caller records
	// CarriedTierBoundUnverified.
	BuilderSigNotDSSE BuilderSigTier = iota
	// BuilderSigTransportOnly means the envelope is a DSSE envelope whose builder
	// signature could not be verified against any known, non-revoked bundle key —
	// no bundle, an unknown key id, a revoked key, or a signature that fails to
	// verify. Caller records CarriedTierVerifiedTransportOnly.
	BuilderSigTransportOnly
	// BuilderSigVerified means at least one signature verified against a known,
	// non-revoked bundle key over the DSSE PAE. Caller records
	// CarriedTierBuilderVerified with the returned key id.
	BuilderSigVerified
)

// VerifyBuilderSignature classifies a carried attestation envelope's builder
// signature. It accepts a DSSE envelope wrapping an in-toto Statement, or a bare
// in-toto Statement (which carries no builder signature and yields
// BuilderSigNotDSSE). For a DSSE envelope it recomputes
// PAE("DSSEv1", payloadType, payload) over the RAW (base64-decoded) payload bytes
// and ed25519-verifies each signature against the bundle key its keyid names,
// treating keyid only as a selection hint — the signature itself is the security
// decision (DSSE protocol.md: keyid MUST NOT be used for security decisions).
// The first signature that verifies against a known, non-revoked key wins;
// signatures naming an unknown key are ignored (not failed), and a signature
// naming a revoked key never counts.
//
// It returns a non-nil error only for a DSSE envelope that is structurally
// invalid in a security-relevant way: duplicate JSON keys (a parser-differential
// vector, threat G10), a payloadType that is not application/vnd.in-toto+json, or
// an undecodable base64 payload. A single undecodable signature block is skipped
// rather than fatal (DSSE is multi-signature), so a third party cannot append a
// malformed block to veto a valid one. In every error case the returned tier is
// BuilderSigTransportOnly (never Verified), so a caller that ignores the error
// still fails closed. A bare Statement is NOT an error.
func VerifyBuilderSignature(envelope []byte, lookup KeyLookup, revoked func(keyID string) bool) (BuilderSigTier, string, error) {
	// Reject ambiguous objects up front (G10): if the envelope (or any nested
	// object) repeats a key, a lenient parser could bind bytes other than the
	// ones the signature covers. polypkg refuses to guess.
	if err := rejectDuplicateKeys(envelope); err != nil {
		return BuilderSigTransportOnly, "", err
	}

	var env struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Type        string `json:"_type"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(envelope, &env); err != nil {
		return BuilderSigTransportOnly, "", fmt.Errorf("parse DSSE envelope: %w", err)
	}

	// A bare in-toto Statement (no payloadType/payload) has no builder signature.
	// Distinguish it from a DSSE envelope so the caller records bound-unverified
	// rather than transport-only.
	if env.PayloadType == "" && env.Payload == "" {
		if env.Type != "" {
			return BuilderSigNotDSSE, "", nil
		}
		return BuilderSigTransportOnly, "", errors.New("envelope is neither a DSSE envelope nor an in-toto Statement")
	}

	if env.PayloadType != inTotoPayloadType {
		return BuilderSigTransportOnly, "", fmt.Errorf("DSSE payloadType %q is not %q", env.PayloadType, inTotoPayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return BuilderSigTransportOnly, "", fmt.Errorf("decode DSSE payload: %w", err)
	}

	msg := pae(env.PayloadType, payload)
	for _, s := range env.Signatures {
		if s.KeyID == "" || revoked(s.KeyID) {
			continue // no usable hint, or explicitly revoked: cannot count
		}
		pub, ok := lookup(s.KeyID)
		if !ok {
			continue // unknown key id: ignore, do not fail
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			// DSSE is multi-signature; a single undecodable signature block must
			// not veto the others. Skip it (like an unknown keyid) rather than
			// aborting — otherwise any third party could prepend a garbage block
			// naming a known key to downgrade a validly-signed artifact. A wholly
			// bad envelope simply finds no verifying signature and falls through
			// to transport-only below.
			continue
		}
		if ed25519.Verify(pub, msg, sig) {
			return BuilderSigVerified, s.KeyID, nil
		}
	}
	return BuilderSigTransportOnly, "", nil
}

// pae returns the DSSE Pre-Authentication Encoding of (payloadType, payload):
//
//	"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
//
// SP is a single 0x20; LEN is the ASCII-decimal byte length with no leading
// zeros (secure-systems-lab/dsse protocol.md). body is the RAW decoded payload,
// not its base64 text — signing the base64 form, or the whole JSON, fails to
// verify.
func pae(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// rejectDuplicateKeys errors if any JSON object within data repeats a key. Go's
// encoding/json silently keeps the last value for a duplicate key, so a signed
// payload and the bytes a lenient parser binds could differ (threat G10);
// polypkg refuses such ambiguous documents.
func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	return walkNoDup(dec)
}

// walkNoDup consumes exactly one JSON value from dec, recursing into objects and
// arrays and rejecting any object with a repeated key.
func walkNoDup(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("object key is not a string: %v", keyTok)
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := walkNoDup(dec); err != nil { // the value
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // closing }
			return err
		}
	case '[':
		for dec.More() {
			if err := walkNoDup(dec); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // closing ]
			return err
		}
	}
	return nil
}
