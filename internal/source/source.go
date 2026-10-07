// Package source defines polypkg's source backend interface and ships
// the minimal native backend for fetching signed tarballs over HTTPS.
package source

import (
	"context"
	"errors"
)

// ErrMetadataAbsent reports that an OPTIONAL repository metadata document (the
// trust bundle or revocation list) is not published by this source at all — a
// 404/absent on the DOCUMENT itself, distinct from a present document whose
// detached signature is missing (which is tampering, surfaced as an ordinary
// error). Callers use errors.Is to treat true absence as the trust-on-first-use
// baseline while still refusing a document that vanished after being seen.
var ErrMetadataAbsent = errors.New("repository metadata document absent")

// Backend is implemented by every source backend (native, RPM bridge,
// OCI bridge, etc.). Only the native backend exists.
type Backend interface {
	Name() string
	Fetch(ctx context.Context, artifact string) ([]byte, error)
	FetchSignature(ctx context.Context, artifact string) (string, error)
	// FetchIndex returns the raw source index bytes and its detached minisign
	// signature. Callers MUST verify the signature before parsing the bytes.
	FetchIndex(ctx context.Context) (raw []byte, sig string, err error)
	// FetchTrustDoc returns the raw polypkg.trust/v2 document and its detached
	// minisign signature. Callers MUST verify the signature (under the source's
	// trust_root anchor) before parsing the bytes.
	FetchTrustDoc(ctx context.Context) (raw []byte, sig string, err error)
	// FetchTrustBundle returns the raw polypkg.trust-bundle/v1 document and its
	// detached minisign signature. It returns an error wrapping
	// ErrMetadataAbsent when the source publishes no bundle at all.
	FetchTrustBundle(ctx context.Context) (raw []byte, sig string, err error)
	// FetchRevocationList returns the raw polypkg.revocation-list/v1 document
	// and its detached minisign signature. It returns an error wrapping
	// ErrMetadataAbsent when the source publishes no revocation list at all.
	FetchRevocationList(ctx context.Context) (raw []byte, sig string, err error)
}

// ArtifactRefetcher is an optional capability for backends whose Fetch may
// serve locally cached bytes. Callers assert for it when fetched bytes fail
// signature or hash verification, to distinguish a stale cache entry from a
// genuinely bad artifact before refusing.
type ArtifactRefetcher interface {
	// RefetchArtifact discards any cached copy of artifact and fetches it fresh.
	// The planner calls this when cached bytes fail signature or hash
	// verification: the cache is keyed by base name only, so a repository that
	// republishes different bytes under the same path (hand-rolled layouts;
	// polypkg's own pool is content-addressed) would otherwise wedge the client
	// on the stale entry forever.
	RefetchArtifact(ctx context.Context, artifact string) ([]byte, error)
}
