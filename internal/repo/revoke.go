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

// RevokeOptions describes the revocations to add to the repository's published
// list and the freshness window to stamp. Both target slices may contain
// duplicates and overlap the already-published set; Revoke de-dupes.
type RevokeOptions struct {
	Attestations []string      // blake3:<hex> attestation content-hashes to revoke
	BuilderKeys  []string      // builder key ids to revoke
	ValidFor     time.Duration // freshness window; DefaultValidFor when <= 0
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
// revocation is never silently dropped. The list's own monotonic serial is
// bumped on every call, and a fresh expires is stamped from ValidFor. Callers
// obtain a Builder via NewBuilder, which loads the manifest and decrypts the
// signing key.
func (b *Builder) Revoke(opts RevokeOptions) (RevokeResult, error) {
	if len(opts.Attestations) == 0 && len(opts.BuilderKeys) == 0 {
		return RevokeResult{}, &PublishError{
			Msg:  "nothing to revoke",
			Hint: "pass --attestation <blake3:hash> and/or --builder-key <id>",
		}
	}
	validFor := opts.ValidFor
	if validFor <= 0 {
		validFor = DefaultValidFor
	}

	lay := b.insp.layout
	outputDir := lay.outputDir
	revPath := filepath.Join(outputDir, revocationsFile)

	// Seed the sets from the currently published list so revocations accumulate.
	atts := map[string]struct{}{}
	keys := map[string]struct{}{}
	prevSerial := uint64(0)
	if raw, err := os.ReadFile(revPath); err == nil { //nolint:gosec // G304: revPath is our own prior published output
		existing, perr := schema.ParseRevocationList(bytes.NewReader(raw))
		if perr != nil {
			return RevokeResult{}, &PublishError{
				Msg:  "existing revocations.json is invalid and cannot be extended",
				Hint: "repair or remove the published revocations.json, then re-run",
				Err:  perr,
			}
		}
		if existing.Source != lay.manifest.Source {
			return RevokeResult{}, &PublishError{
				Msg:  fmt.Sprintf("published revocations.json is for source %q, not %q", existing.Source, lay.manifest.Source),
				Hint: "the output directory already holds another source's revocation list",
			}
		}
		prevSerial = existing.Serial
		for _, h := range existing.RevokedAttestations {
			atts[h] = struct{}{}
		}
		for _, k := range existing.RevokedBuilderKeys {
			keys[k] = struct{}{}
		}
	} else if !os.IsNotExist(err) {
		return RevokeResult{}, fmt.Errorf("read published revocations.json: %w", err)
	}

	for _, h := range opts.Attestations {
		atts[h] = struct{}{}
	}
	for _, k := range opts.BuilderKeys {
		keys[k] = struct{}{}
	}

	now := time.Now().UTC()
	rl := &schema.RevocationList{
		Schema:              revocationListSchema,
		Source:              lay.manifest.Source,
		Serial:              prevSerial + 1,
		IssuedAt:            now.Format(time.RFC3339),
		Expires:             now.Add(validFor).Format(time.RFC3339),
		RevokedAttestations: sortedSet(atts),
		RevokedBuilderKeys:  sortedSet(keys),
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

	if err := os.MkdirAll(outputDir, 0o755); err != nil { //nolint:gosec // G301: output dir is served over HTTP; 0755 is intentional
		return RevokeResult{}, fmt.Errorf("create output directory: %w", err)
	}
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
