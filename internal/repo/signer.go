// Package repo builds, signs, and maintains a polypkg repository: the producer
// counterpart to the consumer's fetch/verify path.
package repo

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"lukechampine.com/blake3"
)

// Keypair is an Ed25519 signing keypair rendered in minisign's legacy "Ed"
// format (pure Ed25519 over raw bytes, no prehash). Public keys and signatures
// it produces verify with both polypkg's trust path and the stock minisign CLI.
type Keypair struct {
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	keyID [8]byte
}

// GenerateKeypair creates a fresh keypair with a random 8-byte key id.
func GenerateKeypair() (*Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("generate key id: %w", err)
	}
	return &Keypair{pub: pub, priv: priv, keyID: id}, nil
}

// KeypairFromSeed reconstructs a keypair from a 32-byte Ed25519 seed and key id.
func KeypairFromSeed(seed []byte, keyID [8]byte) (*Keypair, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Keypair{priv: priv, pub: priv.Public().(ed25519.PublicKey), keyID: keyID}, nil
}

// Seed returns the 32-byte Ed25519 seed (the secret to protect at rest).
func (k *Keypair) Seed() []byte { return k.priv.Seed() }

// KeyID returns the raw 8-byte key id.
func (k *Keypair) KeyID() [8]byte { return k.keyID }

// KeyIDHex returns the 16-lowercase-hex-char key id used in trust documents.
func (k *Keypair) KeyIDHex() string { return hex.EncodeToString(k.keyID[:]) }

// PublicKeyBase64 returns base64("Ed" + keyID + pub), the form stored in a
// trust document's keys[].pubkey and in a .pub file body.
func (k *Keypair) PublicKeyBase64() string {
	bin := append([]byte{'E', 'd'}, k.keyID[:]...)
	bin = append(bin, k.pub...)
	return base64.StdEncoding.EncodeToString(bin)
}

// PublicKeyFile returns minisign .pub file content with the given comment.
func (k *Keypair) PublicKeyFile(comment string) string {
	return "untrusted comment: " + comment + "\n" + k.PublicKeyBase64() + "\n"
}

// SignWithComment returns a detached .minisig over data. trustedComment is the
// bare comment text (without the "trusted comment: " prefix). The global
// signature covers sig+trustedComment so it cannot be altered post-hoc.
func (k *Keypair) SignWithComment(data []byte, untrustedComment, trustedComment string) string {
	sig := ed25519.Sign(k.priv, data)
	sigBin := append([]byte{'E', 'd'}, k.keyID[:]...)
	sigBin = append(sigBin, sig...)
	// Global signature input: raw sig bytes concatenated with the trusted comment
	// text (no prefix). This matches go-minisign's verifier which checks
	// Verify(pub, append(sig[:], TrustedComment[17:]...), globalSig).
	globalMsg := append(append([]byte{}, sig...), []byte(trustedComment)...)
	global := ed25519.Sign(k.priv, globalMsg)
	return "untrusted comment: " + untrustedComment + "\n" +
		base64.StdEncoding.EncodeToString(sigBin) + "\n" +
		"trusted comment: " + trustedComment + "\n" +
		base64.StdEncoding.EncodeToString(global) + "\n"
}

// SignArtifact signs an artifact, binding name/version/blake3-hash in the
// trusted comment exactly as the consumer's trust path requires.
func (k *Keypair) SignArtifact(name, version string, data []byte) string {
	tc := fmt.Sprintf("name=%s version=%s hash=%s", name, version, ContentHash(data))
	return k.SignWithComment(data, "polypkg artifact signature", tc)
}

// SignAttestation signs an in-toto attestation document, binding
// name/version and the attestation bytes' own blake3 to the trusted
// comment exactly like SignArtifact (the consumer parses both with the
// same Claims accessor).
func (k *Keypair) SignAttestation(name, version string, data []byte) string {
	tc := fmt.Sprintf("name=%s version=%s hash=%s", name, version, ContentHash(data))
	return k.SignWithComment(data, "polypkg attestation signature", tc)
}

// SignIndex signs index bytes, binding the monotonic serial in the trusted
// comment as the consumer requires.
func (k *Keypair) SignIndex(serial uint64, ts string, data []byte) string {
	tc := fmt.Sprintf("serial=%d ts=%s", serial, ts)
	return k.SignWithComment(data, "polypkg index signature", tc)
}

// SignTrust signs a trust document. The consumer does not constrain its trusted
// comment; we still carry the serial for operator legibility.
func (k *Keypair) SignTrust(serial uint64, data []byte) string {
	return k.SignWithComment(data, "polypkg trust signature", fmt.Sprintf("serial=%d", serial))
}

// SignTrustBundle signs a polypkg.trust-bundle/v1 document. Like SignTrust, the
// consumer does not constrain the trusted comment; the serial is carried for
// operator legibility (the authoritative serial is the one inside the signed
// document body).
func (k *Keypair) SignTrustBundle(serial uint64, data []byte) string {
	return k.SignWithComment(data, "polypkg trust-bundle signature", fmt.Sprintf("serial=%d", serial))
}

// SignRevocationList signs a polypkg.revocation-list/v1 document, carrying the
// serial in the trusted comment for operator legibility.
func (k *Keypair) SignRevocationList(serial uint64, data []byte) string {
	return k.SignWithComment(data, "polypkg revocation-list signature", fmt.Sprintf("serial=%d", serial))
}

// SignPoolManifest signs an export-bundle completeness manifest. It uses the
// same key/role as the index (spec §10.9 E-2): the manifest attests which blobs
// a bundle contains, and is trusted iff the repo's index signature is trusted.
func (k *Keypair) SignPoolManifest(serial uint64, data []byte) string {
	return k.SignWithComment(data, "polypkg pool-manifest signature", fmt.Sprintf("serial=%d", serial))
}

// ContentHash returns the "blake3:<hex>" digest used as the index content_hash.
func ContentHash(b []byte) string {
	h := blake3.New(32, nil)
	_, _ = h.Write(b)
	return "blake3:" + hex.EncodeToString(h.Sum(nil))
}
