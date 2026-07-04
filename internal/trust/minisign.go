// Package trust handles signature verification for polypkg manifests
// and source artifacts using minisign (Ed25519), and the source trust model
// (multi-key trust documents, rotation, revocation, and anti-rollback).
package trust

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jedisct1/go-minisign"
)

const trustedCommentPrefix = "trusted comment: "

// ErrSignatureMismatch marks a cryptographic signature-verification failure:
// the signature is malformed or does not verify over the data under the
// selected key. It is distinct from authorization failures (revoked key, key
// not in the trust set, wrong role) which precede the crypto check and carry
// their own actionable messages. Callers collapse the detail behind this
// sentinel — distinguishing "malformed" from "does not match" would only help
// an attacker probe the verifier — while still letting policy failures surface
// distinctly.
var ErrSignatureMismatch = errors.New("signature verification failed")

// verifyParsed verifies sig over data under an already-decoded public key and
// returns the authenticated trusted comment with its prefix stripped.
func verifyParsed(pk minisign.PublicKey, data []byte, sig string) (string, error) {
	s, err := minisign.DecodeSignature(sig)
	if err != nil {
		return "", fmt.Errorf("%w: malformed signature", ErrSignatureMismatch)
	}
	ok, err := pk.Verify(data, s)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSignatureMismatch, err)
	}
	if !ok {
		return "", fmt.Errorf("%w: signature does not match data", ErrSignatureMismatch)
	}
	return strings.TrimPrefix(s.TrustedComment, trustedCommentPrefix), nil
}

// verifyMinisign verifies sig over data under pubKey (the content of a .pub
// file) and returns the authenticated trusted comment and the signing key's
// 8-byte KeyId. go-minisign authenticates the trusted comment via its
// global-signature check, so the returned comment is tamper-proof.
func verifyMinisign(pubKey string, data []byte, sig string) (comment string, keyID [8]byte, err error) {
	pk, err := minisign.DecodePublicKey(pubKey)
	if err != nil {
		return "", keyID, fmt.Errorf("parse public key: %w", err)
	}
	c, err := verifyParsed(pk, data, sig)
	return c, pk.KeyId, err
}

// Verify checks that sig is a valid minisign signature of data, made by the
// holder of the secret key corresponding to pubKey. pubKey is the full content
// of a minisign .pub file; sig is the full content of a .minisig file.
func Verify(pubKey string, data []byte, sig string) error {
	_, _, err := verifyMinisign(pubKey, data, sig)
	return err
}

// sigKeyID decodes only the KeyId from a minisign signature, used to select the
// candidate signing key before its public key (and full verification) is known.
func sigKeyID(sig string) ([8]byte, error) {
	var z [8]byte
	s, err := minisign.DecodeSignature(sig)
	if err != nil {
		return z, fmt.Errorf("decode signature: %w", err)
	}
	return s.KeyId, nil
}
