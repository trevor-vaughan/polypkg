package repo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// revocationListSchema is the schema tag every polypkg.revocation-list/v1
// document must carry (enforced by the embedded JSON Schema on parse).
const revocationListSchema = "polypkg.revocation-list/v1"

// revocationsFile is the published revocation-list filename, served from the
// repository output-dir root alongside index.json; the detached signature is
// the same name plus ".minisig". These names are fixed by the consumer fetch
// path (internal/source.FetchRevocationList).
const revocationsFile = "revocations.json"

// RevokeOptions describes the revocations to add to, or prune from, the
// repository's published list, and the freshness window to stamp. All target
// slices may contain duplicates and overlap the already-published set; Revoke
// de-dupes. Additions and removals are mutually exclusive within one call.
type RevokeOptions struct {
	Attestations       []string      // blake3:<hex> attestation content-hashes to revoke
	BuilderKeys        []string      // builder key ids to revoke
	RemoveAttestations []string      // attestation hashes to drop from the published list (prune)
	RemoveBuilderKeys  []string      // builder key ids to drop from the published list (prune)
	ValidFor           time.Duration // freshness window; DefaultValidFor when <= 0
}

// RevokeResult reports the authored-and-signed revocation list.
type RevokeResult struct {
	RevocationsPath     string
	SignaturePath       string
	Serial              uint64
	RevokedAttestations []string
	RevokedBuilderKeys  []string
}

// Revoke authors, signs, and publishes the repository's revocation list
// (revocations.json + .minisig) in the output directory. It is cumulative: the
// currently published list is loaded and the new targets are merged in, so a
// revocation is never silently dropped. Passing Remove* instead prunes those
// targets from the published list (e.g. once mirrors have long since dropped
// the underlying artifact). Additions and removals cannot be mixed in one
// call. The list's own monotonic serial is bumped on every call, and a fresh
// expires is stamped from ValidFor. Callers obtain a Builder via NewBuilder,
// which loads the manifest and decrypts the signing key.
func (b *Builder) Revoke(opts RevokeOptions) (RevokeResult, error) {
	addN := len(opts.Attestations) + len(opts.BuilderKeys)
	remN := len(opts.RemoveAttestations) + len(opts.RemoveBuilderKeys)
	if addN == 0 && remN == 0 {
		return RevokeResult{}, &PublishError{
			Msg:  "nothing to revoke",
			Hint: "add with --attestation/--builder-key, or prune with --remove/--remove-builder-key",
		}
	}
	if addN > 0 && remN > 0 {
		return RevokeResult{}, &PublishError{
			Msg:  "cannot add and remove revocations in one invocation",
			Hint: "run separate `repo revoke` commands for additions and removals",
		}
	}
	validFor := opts.ValidFor
	if validFor <= 0 {
		validFor = DefaultValidFor
	}

	existing, err := b.loadPublishedRevocationList()
	if err != nil {
		return RevokeResult{}, err
	}
	if remN > 0 && existing == nil {
		return RevokeResult{}, &PublishError{
			Msg:  "no published revocation list to prune",
			Hint: "there is no revocations.json in the output directory",
		}
	}
	prevSerial := uint64(0)
	if existing != nil {
		prevSerial = existing.Serial
	}

	atts, keys, _ := mergedSets(existing, opts.Attestations, opts.BuilderKeys, opts.RemoveAttestations, opts.RemoveBuilderKeys)
	return b.publishRevocationList(prevSerial, atts, keys, validFor)
}

// loadPublishedRevocationList reads and parses this repo's published
// revocations.json. Returns (nil, nil) when absent. Errors on a corrupt file or
// one bound to a different source (never silently overwritten).
func (b *Builder) loadPublishedRevocationList() (*schema.RevocationList, error) {
	revPath := filepath.Join(b.insp.layout.outputDir, revocationsFile)
	raw, err := os.ReadFile(revPath) //nolint:gosec // G304: our own prior published output
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read published revocations.json: %w", err)
	}
	rl, perr := schema.ParseRevocationList(bytes.NewReader(raw))
	if perr != nil {
		return nil, &PublishError{
			Msg:  "existing revocations.json is invalid and cannot be extended",
			Hint: "repair or remove the published revocations.json, then re-run",
			Err:  perr,
		}
	}
	if rl.Source != b.insp.layout.manifest.Source {
		return nil, &PublishError{
			Msg:  fmt.Sprintf("published revocations.json is for source %q, not %q", rl.Source, b.insp.layout.manifest.Source),
			Hint: "the output directory already holds another source's revocation list",
		}
	}
	return rl, nil
}

// mergedSets applies additions and removals to the existing published sets and
// returns the resulting sorted slices plus whether membership changed. Empty
// results are nil (so the JSON omitempty tag drops the field).
func mergedSets(existing *schema.RevocationList, addAtts, addKeys, remAtts, remKeys []string) (atts, keys []string, changed bool) {
	attSet := map[string]struct{}{}
	keySet := map[string]struct{}{}
	if existing != nil {
		for _, h := range existing.RevokedAttestations {
			attSet[h] = struct{}{}
		}
		for _, k := range existing.RevokedBuilderKeys {
			keySet[k] = struct{}{}
		}
	}
	beforeA, beforeK := len(attSet), len(keySet)
	for _, h := range addAtts {
		attSet[h] = struct{}{}
	}
	for _, k := range addKeys {
		keySet[k] = struct{}{}
	}
	removed := 0
	for _, h := range remAtts {
		if _, ok := attSet[h]; ok {
			delete(attSet, h)
			removed++
		}
	}
	for _, k := range remKeys {
		if _, ok := keySet[k]; ok {
			delete(keySet, k)
			removed++
		}
	}
	changed = len(attSet) != beforeA || len(keySet) != beforeK || removed > 0
	return sortedSet(attSet), sortedSet(keySet), changed
}

// publishRevocationList signs and atomically writes the next revocation list
// (serial = prevSerial+1, fresh expires = now+validFor) to the output directory.
func (b *Builder) publishRevocationList(prevSerial uint64, atts, keys []string, validFor time.Duration) (RevokeResult, error) {
	now := time.Now().UTC()
	rl := &schema.RevocationList{
		Schema:              revocationListSchema,
		Source:              b.insp.layout.manifest.Source,
		Serial:              prevSerial + 1,
		IssuedAt:            now.Format(time.RFC3339),
		Expires:             now.Add(validFor).Format(time.RFC3339),
		RevokedAttestations: atts,
		RevokedBuilderKeys:  keys,
	}

	doc, err := json.MarshalIndent(rl, "", "  ")
	if err != nil {
		return RevokeResult{}, fmt.Errorf("marshal revocation list: %w", err)
	}
	// Never publish a document the consumer's strict parser would reject (e.g. a
	// malformed --attestation that is not blake3:<hex>): validate before signing.
	if _, err := schema.ParseRevocationList(bytes.NewReader(doc)); err != nil {
		return RevokeResult{}, &PublishError{
			Msg:  "authored revocation list is not schema-valid",
			Hint: "attestation hashes must be blake3:<hex>; builder key ids must be non-empty",
			Err:  err,
		}
	}

	sig := b.key.SignRevocationList(rl.Serial, doc)

	outputDir := b.insp.layout.outputDir
	if err := os.MkdirAll(outputDir, 0o755); err != nil { //nolint:gosec // G301: output dir is served over HTTP; 0755 is intentional
		return RevokeResult{}, fmt.Errorf("create output directory: %w", err)
	}
	revPath := filepath.Join(outputDir, revocationsFile)
	if err := writeAtomicBatch([]publishFile{
		{path: revPath, body: doc},
		{path: revPath + ".minisig", body: []byte(sig)},
	}); err != nil {
		return RevokeResult{}, err
	}

	return RevokeResult{
		RevocationsPath:     revPath,
		SignaturePath:       revPath + ".minisig",
		Serial:              rl.Serial,
		RevokedAttestations: rl.RevokedAttestations,
		RevokedBuilderKeys:  rl.RevokedBuilderKeys,
	}, nil
}

// PropagateRevocations merges atts/keys into the published revocation list
// (additive, cumulative) on behalf of an automated re-publisher (mirror pull).
// It emits a new signed list only when there is something to publish: the
// merged set is non-empty, and either the set changed, no list exists yet, or
// the published list has dropped to/below its freshness half-life — so a
// periodic pull refreshes downstream freshness without churning the serial on
// a no-op run. When there are no upstream revocations and no published list
// yet, it is a strict no-op: an empty list is never brought into existence,
// since that would saddle a clean mirror with a revocation-freshness
// obligation for no benefit. Returns (result, emitted, err); emitted is false
// when nothing was written.
func (b *Builder) PropagateRevocations(atts, keys []string, validFor time.Duration) (RevokeResult, bool, error) {
	if validFor <= 0 {
		validFor = DefaultValidFor
	}
	existing, err := b.loadPublishedRevocationList()
	if err != nil {
		return RevokeResult{}, false, err
	}
	mergedA, mergedK, changed := mergedSets(existing, atts, keys, nil, nil)
	if existing == nil && len(mergedA) == 0 && len(mergedK) == 0 {
		// Nothing to revoke and no published list yet: do not bring an empty
		// revocation list into existence (it would saddle a clean mirror with a
		// revocation-freshness obligation for no benefit).
		return RevokeResult{}, false, nil
	}
	renew := changed || existing == nil || revocationBelowHalfLife(existing.Expires, validFor)
	if !renew {
		return RevokeResult{}, false, nil
	}
	prevSerial := uint64(0)
	if existing != nil {
		prevSerial = existing.Serial
	}
	res, err := b.publishRevocationList(prevSerial, mergedA, mergedK, validFor)
	if err != nil {
		return RevokeResult{}, false, err
	}
	return res, true, nil
}

// revocationBelowHalfLife reports whether a published expires is missing,
// unparseable, or has at most half of validFor remaining — the same renewal
// trigger computeExpires (build.go) uses for the index.
func revocationBelowHalfLife(expires string, validFor time.Duration) bool {
	if expires == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		return true
	}
	return time.Until(t) <= validFor/2
}

// sortedSet returns the set's members in deterministic sorted order, or nil when
// empty (so the JSON omitempty tag drops the field rather than emitting []).
func sortedSet(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
