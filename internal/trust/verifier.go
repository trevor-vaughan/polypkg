package trust

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jedisct1/go-minisign"

	"github.com/trevor-vaughan/polypkg/internal/platform"
)

// AnchorError reports that a source's trust_root anchor is not a valid minisign
// public key. It is returned by NewVerifier, which parses the anchor eagerly so
// a misconfigured trust_root (e.g. pointed at a non-key file) fails up front
// with a clear cause instead of surfacing the library's "Invalid encoded public
// key" deep inside trust-document verification. The library detail is kept in
// the chain (Unwrap) for logs; the CLI frames the path-aware user message.
type AnchorError struct {
	Err error
}

func (e *AnchorError) Error() string {
	return "anchor is not a valid minisign public key"
}

func (e *AnchorError) Unwrap() error { return e.Err }

// Role identifies what a signing key is authorised to sign.
type Role string

// The roles a signing key may hold.
const (
	RoleIndex       Role = "index"
	RoleArtifact    Role = "artifact"
	RoleAttestation Role = "attestation"
)

// Claims are the authenticated assertions extracted from a verified signature.
type Claims struct {
	KeyID  string            // 16 lowercase hex chars
	Role   Role              // the role the signature was verified against
	Values map[string]string // authenticated trusted-comment key=value fields
}

// Artifact returns the name/version/platform/hash an artifact signature
// claims. The trusted comment must carry platform=: either the reserved token
// platform.Any, returned as "" to match a platform-agnostic
// schema.IndexEntry.Platform, or a platform that passes
// platform.ValidateConsumer (the consumer grammar, so a newer publisher's
// variant platform still parses and is then rejected by the entry comparison).
// A comment without platform= is refused rather than read as "any": otherwise
// a genuinely signed pre-platform signature could be replayed to bind a darwin
// artifact to a linux entry.
func (c Claims) Artifact() (name, version, plat, hash string, err error) {
	name, version, hash, err = c.nameVersionHash("artifact")
	if err != nil {
		return "", "", "", "", err
	}
	plat = c.Values["platform"]
	switch plat {
	case "":
		return "", "", "", "", fmt.Errorf("artifact signature comment missing platform")
	case platform.Any:
		return name, version, "", hash, nil
	}
	if verr := platform.ValidateConsumer(plat); verr != nil {
		return "", "", "", "", fmt.Errorf("artifact signature comment: %w", verr)
	}
	return name, version, plat, hash, nil
}

// Attestation returns the name/version/hash an attestation's transport
// signature claims, erroring if any is absent or the hash is not a blake3
// digest. Unlike Artifact it binds no platform: an attestation binds to its
// artifact by digest, which is already per-platform.
func (c Claims) Attestation() (name, version, hash string, err error) {
	return c.nameVersionHash("attestation")
}

// nameVersionHash extracts the name/version/hash fields every artifact and
// attestation trusted comment carries. kind labels the errors.
func (c Claims) nameVersionHash(kind string) (name, version, hash string, err error) {
	name, version, hash = c.Values["name"], c.Values["version"], c.Values["hash"]
	if name == "" || version == "" || hash == "" {
		return "", "", "", fmt.Errorf("%s signature comment missing name/version/hash", kind)
	}
	if !strings.HasPrefix(hash, "blake3:") || len(hash) <= len("blake3:") {
		return "", "", "", fmt.Errorf("%s signature comment hash %q is not a blake3 digest", kind, hash)
	}
	return name, version, hash, nil
}

// IndexSerial returns the monotonic serial an index signature claims.
func (c Claims) IndexSerial() (uint64, error) {
	s := c.Values["serial"]
	if s == "" {
		return 0, fmt.Errorf("index signature comment missing serial")
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("index signature comment serial %q is not a uint64: %w", s, err)
	}
	return n, nil
}

// Keyring is a verified set of signing keys for one source.
type Keyring interface {
	// Verify selects the signing key by the signature's KeyId, enforces
	// active + role + not-revoked, verifies the signature over data, and returns
	// the authenticated claims.
	Verify(role Role, data []byte, sig string) (Claims, error)
}

// Verifier loads a source's signed trust document and yields a Keyring, and
// loads the source's signed trust bundle and revocation list (all anchored by
// the same trust_root).
type Verifier interface {
	// LoadTrust verifies the trust document under the anchor, enforces freshness
	// (with per-source accept_expiry_until grace) BEFORE the serial-rollback
	// floor lastTrustSerial, and returns the keyring, the document's serial, and
	// whether freshness was graced.
	LoadTrust(doc []byte, sig string, lastTrustSerial uint64, acceptUntil string) (Keyring, uint64, bool, error)
	// LoadBundle verifies the trust bundle under the anchor, enforces freshness
	// (with grace) before the serial floor lastSerial, and returns the queryable
	// bundle, its serial, and whether freshness was graced.
	LoadBundle(doc []byte, sig string, lastSerial uint64, acceptUntil string) (*Bundle, uint64, bool, error)
	// LoadRevocationList verifies the revocation list under the anchor, enforces
	// freshness (with grace) before the serial floor lastSerial, and returns the
	// queryable revocations, its serial, whether freshness was graced, and the
	// list's RFC3339 expires (for the caller to persist as informational state).
	LoadRevocationList(doc []byte, sig string, lastSerial uint64, acceptUntil string) (*Revocations, uint64, bool, string, error)
}

// NewVerifier returns the trust Verifier for the given source backend type,
// anchored by anchorPub (the trust_root .pub content) and bound to sourceName
// (the trust document must name this source). M2 supports only the native
// backend's minisign scheme.
func NewVerifier(sourceType, anchorPub, sourceName string) (Verifier, error) {
	switch sourceType {
	case "polypkg-native":
		// Parse the anchor up front so a misconfigured trust_root fails here
		// with a typed AnchorError, not deep inside trust-document verification.
		if _, err := minisign.DecodePublicKey(anchorPub); err != nil {
			return nil, &AnchorError{Err: err}
		}
		return &minisignVerifier{anchorPub: anchorPub, source: sourceName}, nil
	default:
		return nil, fmt.Errorf("no trust verifier for source type %q", sourceType)
	}
}
