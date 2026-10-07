package repo

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// sigstoreRootsHint is the shared next step for every sigstore_roots failure.
const sigstoreRootsHint = "each sigstore_roots entry in polypkg-repo.yaml must name a sigstore trusted_root.json, relative to the manifest's directory unless absolute; fix or remove the entry"

// sigstoreRootsFromFile converts one sigstore trusted_root.json — the
// dev.sigstore.trustedroot document sigstore tooling and TUF distribute — into
// polypkg's mirrored schema.SigstoreRoot entries. entry is the path as the
// manifest spells it (used in every error, so the operator can find it); path
// is that entry resolved against the manifest directory.
//
// Each Fulcio certificate authority becomes one root, windowed by the CA's own
// validity period (an open-ended CA yields an open-ended root) and carrying
// every Rekor and CT log key whose validity period overlaps that window (less
// the keys consumers could never match; see overlappingLogKeys). The
// consumer (attest.SigstoreTrustedMaterial) applies a root's single window to
// all of its keys, so a log key that is valid for only part of the CA's window
// is trusted for the whole of it. That widening is inherent in the
// one-window-per-root model polypkg mirrors; the CA window still bounds which
// certificates verify.
//
// Roots are returned newest CA first. trust.SelectSigstoreRoot picks the first
// root whose window contains a bundle's integrated time, and where CA windows
// overlap (a CA rotation) a bundle signed during the overlap is far more likely
// to chain to the newer CA.
//
// Every converted root is loaded through attest.SigstoreTrustedMaterial before
// it is returned, so a root consumers could not load fails the build here
// rather than at install time.
func sigstoreRootsFromFile(entry, path string) ([]schema.SigstoreRoot, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is the operator-declared sigstore_roots entry
	if err != nil {
		return nil, &PublishError{Msg: fmt.Sprintf("cannot read sigstore root %s", entry), Hint: sigstoreRootsHint, Err: err}
	}
	tr, err := root.NewTrustedRootFromJSON(data)
	if err != nil {
		return nil, &PublishError{Msg: fmt.Sprintf("sigstore root %s is not a valid sigstore trusted root", entry), Hint: sigstoreRootsHint, Err: err}
	}

	cas := make([]*root.FulcioCertificateAuthority, 0, len(tr.FulcioCertificateAuthorities()))
	for _, ca := range tr.FulcioCertificateAuthorities() {
		fca, ok := ca.(*root.FulcioCertificateAuthority)
		if !ok {
			return nil, &PublishError{Msg: fmt.Sprintf("sigstore root %s has a certificate authority polypkg cannot mirror", entry), Hint: sigstoreRootsHint}
		}
		cas = append(cas, fca)
	}
	if len(cas) == 0 {
		return nil, &PublishError{Msg: fmt.Sprintf("sigstore root %s lists no Fulcio certificate authority", entry), Hint: sigstoreRootsHint}
	}
	slices.SortStableFunc(cas, func(a, b *root.FulcioCertificateAuthority) int {
		return b.ValidityPeriodStart.Compare(a.ValidityPeriodStart)
	})

	roots := make([]schema.SigstoreRoot, 0, len(cas))
	for _, ca := range cas {
		start, end := ca.ValidityPeriodStart, ca.ValidityPeriodEnd
		if start.IsZero() {
			return nil, &PublishError{
				Msg:  fmt.Sprintf("sigstore root %s has a certificate authority (%s) with no validity start", entry, ca.URI),
				Hint: sigstoreRootsHint,
			}
		}
		from := start.UTC().Format(time.RFC3339Nano)
		if !end.IsZero() && end.Before(start) {
			return nil, &PublishError{
				Msg:  fmt.Sprintf("sigstore root %s has a certificate authority (%s, valid from %s) whose validity ends before it starts", entry, ca.URI, from),
				Hint: sigstoreRootsHint,
			}
		}
		rekor, err := overlappingLogKeys(tr.RekorLogs(), start, end)
		if err != nil {
			return nil, &PublishError{Msg: fmt.Sprintf("sigstore root %s has a Rekor log key polypkg cannot mirror", entry), Hint: sigstoreRootsHint, Err: err}
		}
		if len(rekor) == 0 {
			return nil, &PublishError{
				Msg:  fmt.Sprintf("sigstore root %s has no Rekor log key whose validity overlaps its certificate authority (%s, valid from %s)", entry, ca.URI, from),
				Hint: sigstoreRootsHint,
			}
		}
		ctlog, err := overlappingLogKeys(tr.CTLogs(), start, end)
		if err != nil {
			return nil, &PublishError{Msg: fmt.Sprintf("sigstore root %s has a CT log key polypkg cannot mirror", entry), Hint: sigstoreRootsHint, Err: err}
		}

		chain := make([]string, 0, 1+len(ca.Intermediates))
		chain = append(chain, base64.StdEncoding.EncodeToString(ca.Root.Raw))
		for _, ic := range ca.Intermediates {
			chain = append(chain, base64.StdEncoding.EncodeToString(ic.Raw))
		}
		r := schema.SigstoreRoot{ValidFrom: from, FulcioCA: chain, RekorKeys: rekor, CTLogKeys: ctlog}
		if !end.IsZero() {
			r.ValidUntil = end.UTC().Format(time.RFC3339Nano)
		}
		if _, err := attest.SigstoreTrustedMaterial(r); err != nil {
			return nil, &PublishError{
				Msg:  fmt.Sprintf("sigstore root %s has a certificate authority (%s, valid from %s) consumers cannot load", entry, ca.URI, from),
				Hint: sigstoreRootsHint,
				Err:  err,
			}
		}
		roots = append(roots, r)
	}
	return roots, nil
}

// overlappingLogKeys returns the base64 DER (SubjectPublicKeyInfo) key of every
// log in logs whose validity period overlaps [start, end], ordered by log id so
// the output is deterministic (logs is a map). A zero end is open-ended, on
// either side.
//
// A mirrored root carries bare keys, not log ids: consumers re-derive each log
// id as the SHA-256 of the key's DER and assume SHA-256 Merkle trees
// (attest.SigstoreTrustedMaterial). A log whose declared id is anything else
// (Rekor v2 logs, such as log2025-1.rekor.sigstore.dev, are identified
// differently), or whose tree is not SHA-256, could never match a bundle's
// entry once mirrored, so it is skipped. Bundles logged only there stay
// unverifiable until the mirrored root can carry log ids.
func overlappingLogKeys(logs map[string]*root.TransparencyLog, start, end time.Time) ([]string, error) {
	var keys []string
	for _, id := range slices.Sorted(maps.Keys(logs)) {
		l := logs[id]
		if !windowsOverlap(start, end, l.ValidityPeriodStart, l.ValidityPeriodEnd) || l.HashFunc != crypto.SHA256 {
			continue
		}
		der, err := x509.MarshalPKIXPublicKey(l.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("marshal log %s public key: %w", id, err)
		}
		if derived := sha256.Sum256(der); !bytes.Equal(derived[:], l.ID) {
			continue
		}
		keys = append(keys, base64.StdEncoding.EncodeToString(der))
	}
	return keys, nil
}

// windowsOverlap reports whether the closed windows [aStart, aEnd] and
// [bStart, bEnd] share at least one instant. A zero end means open-ended.
// Closed bounds match the consumer's inclusive window check (trust.within).
func windowsOverlap(aStart, aEnd, bStart, bEnd time.Time) bool {
	return (aEnd.IsZero() || !bStart.After(aEnd)) && (bEnd.IsZero() || !bEnd.Before(aStart))
}
