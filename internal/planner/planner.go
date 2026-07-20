// Package planner extracts the load-and-resolve pipeline used by polypkg
// apply and polypkg plan. Given a profile, it fetches and verifies each
// resolved package's artifact, extracts it to a temp dir, and returns the
// (manifest, run entries, projected ownership) tuple that the runner
// would consume.
//
// planner.Plan does NOT begin a substrate transaction and does NOT touch
// the active root. It DOES advance the per-source trust serial high-water
// mark on successful trust verification — callers must hold the
// per-scope apply lock to avoid serial races with concurrent applies.
package planner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"lukechampine.com/blake3"

	"github.com/trevor-vaughan/polypkg/internal/action"
	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/audit"
	"github.com/trevor-vaughan/polypkg/internal/extractstore"
	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/runner"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/source"
	"github.com/trevor-vaughan/polypkg/internal/starlarkeval"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// Options configures a planner invocation.
type Options struct {
	DataHome       string
	StateHome      string
	AuditWriter    audit.Writer
	Scope          string
	StarlarkLimits starlarkeval.Limits
	// BaselineActiveRoot is the absolute active root of the generation the
	// projection will be diffed against (the current generation's
	// generations/<n>/active). When non-empty, the projection expands $ACTIVE
	// in target-carrying actions against it, mirroring the runner's apply-time
	// expansion so a converged system compares equal. Empty on first apply (no
	// baseline) or for apply, where the projected ownership is never diffed
	// (the runner records the authoritative ownership); the projection then
	// keeps the literal "$ACTIVE" placeholder.
	BaselineActiveRoot string
	// ForceCatalogFetch makes FetchCatalog fetch and build the full source
	// catalog even when the scope requests no packages. The install action needs
	// the catalog to resolve a package that is not yet in the profile; without
	// this flag FetchCatalog short-circuits the network when reqs is empty.
	ForceCatalogFetch bool
	// Progress is an optional callback for live phase updates. Called at
	// stage boundaries with (stage, detail). Nil disables all callbacks.
	Progress func(stage, detail string)
	// WeakPolicy controls Recommends installation in Phase 2 of resolution.
	WeakPolicy resolver.WeakPolicy
	// AttestationPolicy governs packages whose index entry carries NO
	// attestations: "warn" (default when empty) installs with a warning,
	// "require" refuses, "off" installs silently. A PRESENT attestation is
	// hard-verified in every mode (D-C10) — the policy never bypasses a
	// failed verification.
	AttestationPolicy string
	// PriorManifest is the current generation's manifest (the one active before
	// this apply), or nil on the first apply / when unreadable. The posture
	// floor (2d-2, spec §10.7) reads each package's prior AttestationState from
	// it to refuse a provenance regression. Populated by the CLI from the
	// substrate; nil disables the floor.
	PriorManifest *schema.Manifest
	// RevocationNearExpiry is the window before a revocation list's expiry within
	// which fetch emits a proactive near-expiry warning. Zero disables the warning.
	RevocationNearExpiry time.Duration
}

// progress calls opts.Progress when it is non-nil. Defined as a method so
// call sites stay a single line and nil-guard is never forgotten.
func (o Options) progress(stage, detail string) {
	if o.Progress != nil {
		o.Progress(stage, detail)
	}
}

// Result is the output of planner.Plan.
type Result struct {
	Manifest  *schema.Manifest
	Entries   []runner.RunEntry
	Ownership *schema.Ownership // projected; Stat is zero. Target-carrying actions expand $ACTIVE against Options.BaselineActiveRoot (literal "$ACTIVE" when unset)
	Skipped   []resolver.SkippedRecommend
	Suggests  []resolver.Suggestion
	// AttestationWarnings lists packages installed unattested under the warn
	// policy. Callers surface them on stderr; the verdict itself is recorded
	// per entry in Manifest (D11).
	AttestationWarnings []string
	// AttestationGateDisabled lists packages installed from a source whose
	// per-source attestation tier is "off" (phase 2d-3, threat G8). It is
	// DISTINCT from AttestationWarnings (the warn-policy channel): callers
	// surface it as a prominent SECURITY warning on every apply and record it in
	// the audit log. The disabled gate is also recorded per entry in the
	// manifest (AttestationState.GateDisabled). Package and Source are kept
	// separate so callers can render the warning and emit a structured audit
	// event (discrete source field) without string surgery.
	AttestationGateDisabled []GateDisabledEntry
	// FreshnessGraced lists signed metadata documents accepted under per-source
	// accept_expiry_until grace during the fetch (phase 2e-1, spec §10.9 E-3):
	// expired but within the operator's deadline. Callers surface it as a loud
	// SECURITY line and (on apply) a metadata.expiry_graced audit event. The
	// anti-rollback serial floor was still enforced.
	FreshnessGraced []GracedMetadata
	// NearExpiry lists still-valid signed documents within the near-expiry window
	// at fetch, for the CLI to warn on.
	NearExpiry []NearExpiryMetadata
}

// GateDisabledEntry identifies one package installed with its source's
// attestation gate disabled (tier: off). Package is "<name>-<version>".
type GateDisabledEntry struct {
	Package string
	Source  string
}

// Plan loads packages per the profile, verifies trust, fetches and
// extracts artifacts, hash-binds them to the index, and returns the
// projected (manifest, run entries, ownership) tuple. The Ownership
// projection's paths use the literal "$ACTIVE" placeholder because no
// transaction is open.
//
// Plan advances the per-source trust serial high-water mark on
// successful verification. Callers must hold the scope's apply lock.
//
// On the no-package path (profile has no packages) Plan returns a
// Result with an empty Entries slice and an empty Ownership index.
func Plan(ctx context.Context, p *schema.Profile, opts Options) (*Result, error) {
	if _, ok := p.Scopes[opts.Scope]; !ok {
		return nil, fmt.Errorf("profile has no %q scope to apply", opts.Scope)
	}

	policy := opts.AttestationPolicy
	if policy == "" {
		policy = "warn"
	}

	// Select only this scope's packages. A missing scope key yields a nil map,
	// which ranges zero times (an empty requirement set is a valid no-op apply).
	reqs := make([]resolver.Requirement, 0)
	for name, ref := range p.Packages[opts.Scope] {
		reqs = append(reqs, resolver.Requirement{Name: name, VersionRange: ref.Version})
	}

	var resolved []resolver.Resolved
	var skipped []resolver.SkippedRecommend
	var suggests []resolver.Suggestion
	var fr *FetchResult
	var freshnessGraced []GracedMetadata
	var nearExpiry []NearExpiryMetadata

	if len(reqs) > 0 {
		var err error
		fr, err = FetchCatalog(ctx, p, opts)
		if err != nil {
			return nil, err
		}
		freshnessGraced = fr.FreshnessGraced
		nearExpiry = fr.NearExpiry
		opts.progress("resolving", "")
		rr, err := resolver.ResolveWithWeak(reqs, fr.Catalog, opts.WeakPolicy)
		if err != nil {
			return nil, fmt.Errorf("resolve: %w", err)
		}
		resolved = rr.Installed
		skipped = rr.Skipped
		suggests = rr.Suggests
	}

	// Per-package anti-downgrade guard (D15): refuse a resolved version below
	// its source's high-water mark unless the profile explicitly pins that
	// exact version (the operator's escape hatch for a pulled release).
	// Resolver-chosen dependencies have no profile entry, so they can never
	// be pinned past the guard.
	//
	// The refusal fires only when the source WITHDREW its top version: an
	// index may legitimately offer several versions of one package at once,
	// and selecting an older entry that the current signed index still
	// carries (a hard dependency pin, an upper-bounded range) is constraint
	// resolution, not a mirror-forced downgrade. When any current offer for
	// the package is >= the HWM, the source rolled nothing back.
	// fr is nil on the no-packages path.
	if fr != nil {
		for i := range resolved {
			e := &resolved[i]
			hw := fr.HighWater[e.Source][e.Name]
			if hw == "" {
				continue
			}
			sel, err1 := semver.NewVersion(e.Version)
			top, err2 := semver.NewVersion(hw)
			if err1 != nil || err2 != nil {
				continue
			}
			if !sel.LessThan(top) || sourceOffers(fr.Catalog, e.Name, top) {
				continue
			}
			if !isExactPin(pinFor(p, opts.Scope, e.Name), e.Version) {
				return nil, fmt.Errorf(
					"refusing to downgrade %s to %s: this source previously offered %s; pin the exact version in the profile to accept the downgrade",
					e.Name, e.Version, hw)
			}
		}
	}

	entries := make([]runner.RunEntry, 0, len(resolved))
	manifestEntries := make([]schema.ManifestEntry, 0, len(resolved))
	var attWarnings []string
	var gateDisabled []GateDisabledEntry

	for i := range resolved {
		e := &resolved[i]
		backend := fr.Backends[e.Source]
		artState := fr.Keyrings[e.Source]
		sourceURL := fr.SourceURLs[e.Source]
		// Per-source attestation posture (2d-1/2d-3). Read once here because the
		// tier: off case (2d-3, threat G8) must lower the EFFECTIVE absence policy
		// for verifyAttestations below (so an unattested package installs instead
		// of being refused by a global require) — and it is the OPPOSITE of the
		// global attestation.policy: off, which is silent. srcOff also skips the
		// require gate + posture floor and drives the loud, recorded warning.
		var srcPol *schema.SourceAttestationPolicy
		var pinnedSigstoreRoot *schema.SigstoreRoot
		if sb, ok := p.Sources.Sources[e.Source]; ok {
			srcPol = sb.Attestation
			pinnedSigstoreRoot = sb.SigstoreRoot
		}
		srcOff := srcPol != nil && srcPol.Tier == schema.AttestationTierOff
		effectivePolicy := policy
		if srcOff {
			effectivePolicy = "off"
		}
		opts.progress("fetching", fmt.Sprintf("%s-%s (%d/%d)", e.Name, e.Version, i+1, len(resolved)))
		data, err := backend.Fetch(ctx, e.Artifact)
		if err != nil {
			return nil, fmt.Errorf("fetch %s-%s: %w", e.Name, e.Version, err)
		}
		sig, err := backend.FetchSignature(ctx, e.Artifact)
		if err != nil {
			return nil, fmt.Errorf("fetch signature for %s-%s: %w", e.Name, e.Version, err)
		}
		staleable, verr := verifyArtifact(data, sig, artState, *e)
		if verr != nil && staleable {
			// Fetch may have served cached bytes, and the cache is keyed by base
			// name with no validation: a repository that republishes different
			// bytes under the same path (hand-rolled layouts; polypkg's own pool
			// is content-addressed) would otherwise wedge the client on the
			// poisoned entry forever. Evict and refetch ONCE, re-running the full
			// verify chain on the fresh bytes; if they still fail — or the
			// backend lacks the capability, or the refetch itself errors — the
			// original terminal error semantics stand.
			if rf, ok := backend.(source.ArtifactRefetcher); ok {
				if fresh, ferr := rf.RefetchArtifact(ctx, e.Artifact); ferr == nil {
					data = fresh
					_, verr = verifyArtifact(data, sig, artState, *e)
				}
			}
		}
		if verr != nil {
			return nil, verr
		}
		// Attestations verify against the fetched artifact bytes/metadata only,
		// so they run BEFORE extraction: a package refused here must not leave
		// its extracted tree lingering in the pkg-extract scratch area.
		attState, carried, attWarn, err := verifyAttestations(ctx, backend, artState, fr.Revocations[e.Source], *e, effectivePolicy)
		if err != nil {
			return nil, err
		}
		if attWarn != "" {
			attWarnings = append(attWarnings, attWarn)
		}

		pkgRoot := extractstore.Dir(opts.StateHome, e.Name, e.Version, e.ContentHash)
		if err := ensureExtracted(data, pkgRoot); err != nil {
			return nil, fmt.Errorf("extract %s-%s: %w", e.Name, e.Version, err)
		}

		// Install-time half of the two-point binding (P6): re-bind each carried
		// external attestation's subjects, by digest, against the bytes that just
		// extracted. Runs post-extraction because it needs the extracted tree; a
		// binding failure here refuses the install (fail closed).
		if err := bindCarriedRefs(carried, data, pkgRoot, fr.Bundles[e.Source], pinnedSigstoreRoot, fr.Revocations[e.Source], attState); err != nil {
			return nil, err
		}

		if srcOff {
			// Per-source attestation OFF (2d-3, threat G8): the operator disabled
			// this source's gate. Record it distinctly and surface a loud,
			// unsuppressible warning every apply — a silent kill-switch is the
			// threat. D-C10 still held above (a PRESENT attestation was
			// hard-verified regardless of policy), so off only waives the require
			// gate + the posture floor, never tamper detection.
			attState.GateDisabled = true
			gateDisabled = append(gateDisabled, GateDisabledEntry{
				Package: fmt.Sprintf("%s-%s", e.Name, e.Version),
				Source:  e.Source,
			})
		} else {
			// Consumer attestation policy gate (2d-1): refuse the install when this
			// source's per-predicate require is not met at an anchored, allow-listed
			// tier. Additive — a source with no attestation block is ungated. Reads
			// the same source bundle bindCarriedRefs used for key resolution.
			if err := enforceAttestationPolicy(attState, srcPol, fr.Bundles[e.Source]); err != nil {
				return nil, fmt.Errorf("%s-%s: %w", e.Name, e.Version, err)
			}

			// Posture floor (2d-2, G3): every predicate type verified in the prior
			// generation must still be verified now, else refuse — unless the operator
			// pinned the exact resolved version. PriorManifest is trusted local
			// generation state a mirror cannot influence; the floor keys by package
			// name across sources (a source-switch downgrade is caught too).
			var priorState *schema.AttestationState
			if opts.PriorManifest != nil {
				for i := range opts.PriorManifest.Entries {
					if opts.PriorManifest.Entries[i].Name == e.Name {
						priorState = opts.PriorManifest.Entries[i].Attestation
						break
					}
				}
			}
			pinnedExact := isExactPin(pinFor(p, opts.Scope, e.Name), e.Version)
			if err := enforcePostureFloor(attState, priorState, pinnedExact); err != nil {
				return nil, fmt.Errorf("%s-%s: %w", e.Name, e.Version, err)
			}
		}

		pkgFile, pkgFileName, err := openPackageFile(pkgRoot)
		if err != nil {
			return nil, err
		}
		pkg, err := schema.ParsePackage(pkgFile, pkgFileName)
		_ = pkgFile.Close()
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", pkgFileName, err)
		}
		for _, reserved := range []string{action.SharedBinDir, action.SharedCompletionsDir, action.SharedApplicationsDir, action.SharedMimeDir, action.SharedManDir} {
			if pkg.Name == reserved {
				return nil, fmt.Errorf("package %q uses the reserved shared-directory name %q", pkg.Name, reserved)
			}
		}
		manifestEntries = append(manifestEntries, schema.ManifestEntry{
			Name:          e.Name,
			Version:       e.Version,
			ContentHash:   e.ContentHash,
			SourceURL:     sourceURL + "/" + e.Artifact,
			Weak:          e.Weak,
			RecommendedBy: e.RecommendedBy,
			Attestation:   attState,
		})
		entries = append(entries, runner.RunEntry{Package: pkg, PkgRoot: pkgRoot})
	}

	host, _ := os.Hostname()
	m := &schema.Manifest{
		Schema:         "polypkg.manifest/v2",
		Scope:          opts.Scope,
		Entries:        manifestEntries,
		WeakDepsPolicy: weakPolicyString(opts.WeakPolicy),
		ProducedBy: schema.ProducedBy{
			Tool:    "polypkg",
			Version: "dev", // caller (apply) overwrites with the real CLI version
			Host:    host,
		},
	}

	rl := schema.ResolveStarlarkLimits(p.Starlark)
	ev := starlarkeval.NewEvaluator(starlarkeval.Limits{
		MaxSteps:       rl.MaxSteps,
		Timeout:        time.Duration(rl.Timeout),
		MaxMemoryBytes: rl.MaxMemoryBytes,
		MaxOutputBytes: rl.MaxOutputBytes,
	})
	// Expand $ACTIVE against the diff baseline's active root so target-carrying
	// actions (path/symlink/alternatives/...) project the same fully-expanded link
	// target the runner stored at apply time; fall back to the literal
	// placeholder when there is no baseline (first apply, or apply itself, where
	// the projection is never diffed). Both the relativized ownership Path and
	// conflict detection are stable under either value (rel strips the root out).
	activeRoot := opts.BaselineActiveRoot
	if activeRoot == "" {
		activeRoot = "$ACTIVE"
	}
	opts.progress("projecting", "")
	own, err := ProjectOwnership(entries, activeRoot, ev, opts.Scope)
	if err != nil {
		return nil, fmt.Errorf("project ownership: %w", err)
	}

	return &Result{Manifest: m, Entries: entries, Ownership: own, Skipped: skipped, Suggests: suggests, AttestationWarnings: attWarnings, AttestationGateDisabled: gateDisabled, FreshnessGraced: freshnessGraced, NearExpiry: nearExpiry}, nil
}

// verifyArtifact runs the full artifact verification chain over data: the
// detached minisign signature, the signed claims binding (name/version/hash),
// and the index content-hash recomputation. staleable reports whether the
// failure could be explained by stale locally cached bytes — the mismatch
// cases a cache eviction and refetch may recover from. Authorization failures
// (revoked key, key not in the trust set, wrong role) and malformed signed
// claims are trust-configuration problems no refetch can fix, so they return
// staleable=false.
func verifyArtifact(data []byte, sig string, keyring trust.Keyring, e resolver.Resolved) (staleable bool, err error) {
	claims, err := keyring.Verify(trust.RoleArtifact, data, sig)
	if err != nil {
		// A cryptographic mismatch (corrupt/tampered bytes, malformed sig)
		// is collapsed into a typed error: distinguishing those failure modes
		// would only help an attacker probe the verifier. Authorization
		// failures (revoked key, key not in the trust set, wrong role) are
		// NOT collapsed — the operator needs those distinct, actionable
		// reasons to fix the repository's trust configuration.
		if errors.Is(err, trust.ErrSignatureMismatch) {
			return true, &ArtifactSignatureError{Name: e.Name, Version: e.Version, Source: e.Source, Err: err}
		}
		return false, fmt.Errorf("signature verification failed for %s-%s: %w", e.Name, e.Version, err)
	}
	cname, cversion, chash, err := claims.Artifact()
	if err != nil {
		return false, fmt.Errorf("artifact %s-%s: %w", e.Name, e.Version, err)
	}
	if cname != e.Name || cversion != e.Version || chash != e.ContentHash {
		return true, fmt.Errorf("artifact signature for %s-%s claims %s-%s/%s, expected %s-%s/%s",
			e.Name, e.Version, cname, cversion, chash, e.Name, e.Version, e.ContentHash)
	}

	h := blake3.New(32, nil)
	if _, err := h.Write(data); err != nil {
		return false, fmt.Errorf("hash %s: %w", e.Name, err)
	}
	computed := "blake3:" + hex.EncodeToString(h.Sum(nil))
	if computed != e.ContentHash {
		return true, fmt.Errorf("hash mismatch for %s-%s: index has %s, artifact is %s",
			e.Name, e.Version, e.ContentHash, computed)
	}
	return false, nil
}

// verifyTransport runs the transport half of the attestation chain over
// attBytes: the detached minisign signature under the attestation role, the
// signed name/version/hash claims binding, and the content-addressed hash
// against the index ref. It is the portion shared by native attestations (whose
// statement is then parsed and subject-bound in verifyAttestation) and
// carried-opaque envelopes (whose subjects are digest-bound against the
// extracted tree after extraction — see bindCarriedRefs). staleable reports
// whether the failure could be explained by stale locally cached bytes (a
// refetch may recover); authorization failures return staleable=false. On
// success, computed carries the blake3 content hash of attBytes.
func verifyTransport(attBytes []byte, attSig string, keyring trust.Keyring, e resolver.Resolved, ref schema.AttestationRef) (staleable bool, computed string, err error) {
	claims, err := keyring.Verify(trust.RoleAttestation, attBytes, attSig)
	if err != nil {
		// Only the collapsed cryptographic mismatch (stale bytes under a fresh
		// signature) is staleable; distinct authorization failures are terminal.
		return errors.Is(err, trust.ErrSignatureMismatch), "", fmt.Errorf("attestation signature for %s-%s: %w", e.Name, e.Version, err)
	}
	cname, cversion, chash, err := claims.Artifact()
	if err != nil {
		// Malformed signed claims are a trust-configuration problem; no refetch can fix them.
		return false, "", fmt.Errorf("attestation claims for %s-%s: %w", e.Name, e.Version, err)
	}
	h := blake3.New(32, nil)
	_, _ = h.Write(attBytes)
	computed = "blake3:" + hex.EncodeToString(h.Sum(nil))
	if cname != e.Name || cversion != e.Version || chash != computed || computed != ref.ContentHash {
		return true, "", fmt.Errorf("attestation binding mismatch for %s-%s", e.Name, e.Version)
	}
	return false, computed, nil
}

// verifyAttestation runs the full per-attestation verification chain over a
// NATIVE (native-jcs) attestation: the transport chain (verifyTransport), the
// in-toto statement parse, the predicate-type check, and the subject-digest
// binding to the artifact. staleable/computed have verifyTransport's semantics
// (every check that consumes attBytes is staleable).
func verifyAttestation(attBytes []byte, attSig string, keyring trust.Keyring, e resolver.Resolved, ref schema.AttestationRef) (staleable bool, computed string, err error) {
	staleable, computed, err = verifyTransport(attBytes, attSig, keyring, e, ref)
	if err != nil {
		return staleable, "", err
	}
	st, err := attest.ParseStatement(attBytes)
	if err != nil {
		return true, "", fmt.Errorf("attestation statement for %s-%s: %w", e.Name, e.Version, err)
	}
	if st.PredicateType != ref.PredicateType {
		return true, "", fmt.Errorf("attestation predicate type mismatch for %s-%s: statement %q, index %q", e.Name, e.Version, st.PredicateType, ref.PredicateType)
	}
	// In-toto semantics: the predicate applies to EACH subject, so the binding
	// subject may sit at any index. Since 2b-1, ParseStatement accepts subjects
	// with any digest algorithm, so a native attestation is bound only if SOME
	// subject carries the artifact's blake3 digest; subjects without a blake3
	// entry reconstruct to the never-matching "blake3:" and are skipped. No
	// blake3 match ⇒ fail closed below.
	bound := false
	for _, s := range st.Subject {
		if "blake3:"+s.Digest["blake3"] == e.ContentHash {
			bound = true
			break
		}
	}
	if !bound {
		return true, "", fmt.Errorf("attestation subject digest does not match artifact for %s-%s", e.Name, e.Version)
	}
	return false, computed, nil
}

// fetchVerifiedAttestation fetches ref's attestation bytes and detached
// signature and runs verify over them. Mirroring verifyArtifact's
// cache-poisoning defense: the base-name-keyed cache can serve stale bytes for
// a same-path republish, so if verify fails in a way stale bytes could explain
// (staleable) and the backend supports it, it evicts and refetches ONCE and
// re-runs verify on the fresh bytes; otherwise the original terminal error
// stands. Returns the bytes that ultimately verified. verify reports
// (staleable, err); a nil err means the returned bytes are trusted.
func fetchVerifiedAttestation(ctx context.Context, backend source.Backend, e resolver.Resolved, ref schema.AttestationRef, verify func(attBytes []byte, attSig string) (staleable bool, err error)) ([]byte, error) {
	attBytes, err := backend.Fetch(ctx, ref.Artifact)
	if err != nil {
		return nil, fmt.Errorf("fetch attestation for %s-%s: %w", e.Name, e.Version, err)
	}
	attSig, err := backend.FetchSignature(ctx, ref.Artifact)
	if err != nil {
		return nil, fmt.Errorf("fetch attestation signature for %s-%s: %w", e.Name, e.Version, err)
	}
	staleable, verr := verify(attBytes, attSig)
	if verr != nil && staleable {
		if rf, ok := backend.(source.ArtifactRefetcher); ok {
			if fresh, ferr := rf.RefetchArtifact(ctx, ref.Artifact); ferr == nil {
				attBytes = fresh
				_, verr = verify(attBytes, attSig)
			}
		}
	}
	if verr != nil {
		return nil, verr
	}
	return attBytes, nil
}

// carriedRef pairs a transport-verified carried-opaque attestation ref with the
// verified envelope bytes, carried from verifyAttestations (pre-extraction) to
// bindCarriedRefs (post-extraction) so the digest re-bind runs against the
// extracted tree without re-fetching or re-verifying the transport chain.
type carriedRef struct {
	ref   schema.AttestationRef
	bytes []byte
}

// verifyAttestations enforces D8/D-C10: a PRESENT attestation must verify
// (signature under the attestation role, claims binding, content-addressed
// hash, statement subject == artifact digest) in EVERY policy mode; only
// ABSENCE consults the policy (warn installs with a warning, require
// refuses, off installs silently). An attestation whose content-hash is on the
// source's revocation list is refused in every policy mode (2c-0), before the
// present/absent split. The returned state is recorded in the generation
// manifest (D11) — only "verified" or "unattested" ever persist.
func verifyAttestations(ctx context.Context, backend source.Backend, keyring trust.Keyring, revocations *trust.Revocations, e resolver.Resolved, policy string) (*schema.AttestationState, []carriedRef, string, error) {
	if len(e.Attestations) == 0 {
		state := &schema.AttestationState{Status: "unattested", PolicyAtInstall: policy}
		switch policy {
		case "require":
			return nil, nil, "", fmt.Errorf("package %s-%s has no attestation and attestation.policy is %q", e.Name, e.Version, policy)
		case "off":
			return state, nil, "", nil
		default: // warn
			return state, nil, fmt.Sprintf("package %s-%s is not attested (installing under attestation.policy=warn)", e.Name, e.Version), nil
		}
	}

	verified := make([]string, 0, len(e.Attestations))
	var carried []carriedRef
	var lastHash string
	for _, ref := range e.Attestations {
		// Revoked-attestation refusal (2c-0): the ref's content_hash is the
		// content-addressed blake3 of the att.json bytes, verified against the
		// fetched bytes below; a revoked hash refuses the install in every
		// policy mode (revocation is absolute, like a failed signature).
		if revocations != nil && revocations.IsAttestationRevoked(ref.ContentHash) {
			return nil, nil, "", fmt.Errorf("package %s-%s attestation %s is revoked", e.Name, e.Version, ref.ContentHash)
		}
		// Carried external provenance (kind: carried-opaque) is transport-verified
		// here — its publisher signature, claims, and content hash are checked
		// against the signed index like any ref — but its subjects are digest-bound
		// AFTER extraction, against the bytes that actually land (two-point binding
		// P6, install half; see bindCarriedRefs). The native in-toto statement parse
		// and subject check are skipped: a DSSE/SBOM envelope is not a bare in-toto
		// Statement. A carried ref cannot be smuggled in by a mirror — the ref list
		// lives inside the signed index (D7).
		if ref.Kind == schema.KindCarriedOpaque {
			vbytes, err := fetchVerifiedAttestation(ctx, backend, e, ref, func(b []byte, s string) (bool, error) {
				staleable, _, verr := verifyTransport(b, s, keyring, e, ref)
				return staleable, verr
			})
			if err != nil {
				return nil, nil, "", err
			}
			carried = append(carried, carriedRef{ref: ref, bytes: vbytes})
			continue
		}
		var computed string
		if _, err := fetchVerifiedAttestation(ctx, backend, e, ref, func(b []byte, s string) (bool, error) {
			staleable, c, verr := verifyAttestation(b, s, keyring, e, ref)
			computed = c
			return staleable, verr
		}); err != nil {
			return nil, nil, "", err
		}
		verified = append(verified, ref.PredicateType)
		lastHash = computed
	}
	return &schema.AttestationState{
		Status:          "verified",
		PredicateTypes:  verified,
		AttestationHash: lastHash,
		PolicyAtInstall: policy,
	}, carried, "", nil
}

// extractedTargets assembles the install-time binding targets from the bytes
// that actually landed: the fetched tarball (scope "artifact") plus every
// regular file under pkgRoot/content (scope "content:<rel>"). Non-regular
// entries — symlinks and the like — are skipped, never followed: a provenance
// subject must resolve to concrete bytes, not a redirect (extraction hardening,
// spec §5.3). A subject whose file was swapped for a symlink therefore finds no
// matching target and fails to bind (fail closed). Hard links never reach here:
// ExtractTarZst drops TypeLink entries, so a hard-linked subject surfaces as an
// absent file and also fails to bind.
func extractedTargets(tarball []byte, pkgRoot string) ([]attest.Target, error) {
	targets := []attest.Target{{Scope: "artifact", Bytes: tarball}}
	contentRoot := filepath.Join(pkgRoot, "content")
	if _, err := os.Stat(contentRoot); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return targets, nil
		}
		return nil, fmt.Errorf("stat extracted content: %w", err)
	}
	walkErr := filepath.WalkDir(contentRoot, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() || d.Type()&fs.ModeType != 0 {
			return nil // skip dirs and non-regular files (symlinks etc.)
		}
		rel, relErr := filepath.Rel(contentRoot, p)
		if relErr != nil {
			return relErr
		}
		body, readErr := os.ReadFile(p) //nolint:gosec // G304: p is under the content-addressed extracted tree
		if readErr != nil {
			return readErr
		}
		targets = append(targets, attest.Target{Scope: "content:" + filepath.ToSlash(rel), Bytes: body})
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk extracted content for binding: %w", walkErr)
	}
	return targets, nil
}

// bindCarriedRefs performs the install-time half of the two-point binding (P6).
// For each transport-verified carried envelope it re-extracts the covered
// subjects (authoritative digests come from the payload, not the advisory index
// field) and re-binds them BY DIGEST against the bytes that actually landed —
// the fetched tarball and the extracted content tree — via attest.BindSubjects
// at the sha256 floor. It is fail-closed: if a carried envelope binds nothing
// installed, the install is refused (tamper, or a publisher who bound nothing).
// The authoritative predicate type comes from the signed payload; a positively
// declared index ref that disagrees is refused (threat G9). Each bound ref is
// recorded on attState with a tier from builder-signature verification
// (attest.VerifyBuilderSignature): builder-verified when a non-revoked bundle key
// that was valid at the attestation's build time (Bundle.BuilderKeyAt) signed the
// DSSE envelope — recording verifying_key_id and, for SLSA, builder_identity;
// verified-transport-only when it is a DSSE envelope that did not so verify (bad
// key, revoked, or out-of-window at build time); or bound-unverified for a bare
// in-toto Statement. Refusing an install on a weak tier is phase 2d, not here.
func bindCarriedRefs(carried []carriedRef, tarball []byte, pkgRoot string, bundle *trust.Bundle, pin *schema.SigstoreRoot, revocations *trust.Revocations, attState *schema.AttestationState) error {
	if len(carried) == 0 {
		return nil
	}
	targets, err := extractedTargets(tarball, pkgRoot)
	if err != nil {
		return err
	}
	// Adapt the source's builder keyring + revocations into the kernel's
	// callbacks, keeping internal/attest free of a trust dependency. A nil bundle
	// (source publishes none) yields a lookup that finds nothing ⇒ every DSSE
	// envelope is verified-transport-only, every bare Statement bound-unverified.
	lookup := func(keyID string) (ed25519.PublicKey, bool) {
		if bundle == nil {
			return nil, false
		}
		bk, ok := bundle.BuilderKey(keyID)
		if !ok || bk.Algo != "ed25519" {
			return nil, false
		}
		pub, derr := base64.StdEncoding.DecodeString(bk.PublicKey)
		if derr != nil || len(pub) != ed25519.PublicKeySize {
			return nil, false // an unusable stored key is treated as unknown (fail closed)
		}
		return ed25519.PublicKey(pub), true
	}
	revoked := func(keyID string) bool {
		return revocations != nil && revocations.IsBuilderKeyRevoked(keyID)
	}
	for i := range carried {
		c := &carried[i]
		info, err := attest.InspectCarried(c.bytes)
		if err != nil {
			return fmt.Errorf("re-extract carried subjects for %s: %w", c.ref.Artifact, err)
		}
		// G9: the authoritative predicate type is the one inside the signed payload.
		// When the signed index ref positively claims a different type, the artifact
		// is mislabeled — refuse (fail closed, like a binding failure). An empty
		// index claim has nothing to mislabel, so the payload's type stands.
		if c.ref.PredicateType != "" && c.ref.PredicateType != info.PredicateType {
			return fmt.Errorf("carried attestation %s predicate type mismatch: index ref says %q, signed payload says %q",
				c.ref.Artifact, c.ref.PredicateType, info.PredicateType)
		}
		materials, err := attest.BindSubjects(info.Subjects, targets)
		if err != nil {
			return fmt.Errorf("carried attestation %s (%s) does not bind the installed bytes: %w", c.ref.Artifact, info.Format, err)
		}
		binding := schema.CarriedBinding{
			PredicateType: info.PredicateType,
			Format:        info.Format,
			SubjectScope:  materials[0].Name,
		}
		if info.Format == schema.FormatSigstoreBundle {
			// Sigstore path (2c-3b): verify the bundle OFFLINE against the source's
			// mirrored SigstoreRoot selected by the bundle's (unverified) integrated
			// time; the kernel re-verifies everything. Any failure — no bundle, no
			// root for that time, adapter error, or verification failure — is
			// fail-closed to verified-transport-only. Identity is recorded, not gated
			// (2d). Subject binding already happened above (P6).
			binding.Tier = schema.CarriedTierVerifiedTransportOnly
			if info.BuildTimeKnown {
				// Root selection (2e-5, spec §10.9 E-6): a consumer-pinned root is
				// AUTHORITATIVE — the source-mirrored root is NOT consulted, closing
				// the D-4 G1 chain-degradation asymmetry. No pin => mirrored root
				// (today's behavior). Both are window-checked by the bundle's Rekor
				// integrated time (info.BuildTime) via one selector; downstream
				// verification is identical either way.
				var sroot schema.SigstoreRoot
				var haveRoot bool
				switch {
				case pin != nil:
					sroot, haveRoot = trust.SelectSigstoreRoot([]schema.SigstoreRoot{*pin}, info.BuildTime)
				case bundle != nil:
					sroot, haveRoot = bundle.SigstoreRootAt(info.BuildTime)
				}
				if haveRoot {
					if tm, terr := attest.SigstoreTrustedMaterial(sroot); terr == nil {
						if verdict, verr := attest.VerifySigstoreBundle(c.bytes, tm); verr == nil && verdict.Verified {
							binding.Tier = schema.CarriedTierVerifiedOffline
							binding.CertificateIdentity = verdict.CertificateIdentity
							binding.CertificateIssuer = verdict.CertificateIssuer
						}
					}
				}
			}
			attState.CarriedBindings = append(attState.CarriedBindings, binding)
			continue
		}
		// Builder-signature verification (2c-1a): the kernel classifies the
		// envelope. A revoked builder key or a structurally-invalid envelope
		// (verr != nil, e.g. duplicate JSON keys) fails closed to transport-only.
		tier, keyID, verr := attest.VerifyBuilderSignature(c.bytes, lookup, revoked)
		switch {
		case verr == nil && tier == attest.BuilderSigVerified:
			binding.Tier = schema.CarriedTierBuilderVerified
			binding.VerifyingKeyID = keyID
			binding.BuilderIdentity = info.SLSABuilderID
			// Window gate (2c-1b): a builder-verified signature additionally
			// requires the signing key to have been valid AT the attestation's
			// build time. A definite out-of-window result (or an unparseable stored
			// window) downgrades to transport-only; an absent build timestamp
			// no-ops (design F1). The keyid is in the bundle (the signature verified
			// against it), so BuilderKeyAt reports only out-of-window / parse error.
			if info.BuildTimeKnown && bundle != nil {
				if _, werr := bundle.BuilderKeyAt(keyID, info.BuildTime); werr != nil {
					binding.Tier = schema.CarriedTierVerifiedTransportOnly
					binding.VerifyingKeyID = ""
					binding.BuilderIdentity = ""
				}
			}
		case verr == nil && tier == attest.BuilderSigNotDSSE:
			binding.Tier = schema.CarriedTierBoundUnverified
		default:
			binding.Tier = schema.CarriedTierVerifiedTransportOnly
		}
		attState.CarriedBindings = append(attState.CarriedBindings, binding)
	}
	return nil
}

// sourceOffers reports whether the merged catalog still carries a candidate
// for name at or above top. The merge is a per-name priority overlay, so the
// candidates for name are exactly the current offers of the source the
// resolved package came from. Non-semver candidate versions cannot exist here
// (BuildCatalog rejects them before the catalog is constructed).
func sourceOffers(cat *resolver.Catalog, name string, top *semver.Version) bool {
	for _, v := range cat.Versions(name) {
		if cv, err := semver.NewVersion(v); err == nil && !cv.LessThan(top) {
			return true
		}
	}
	return false
}

// isExactPin reports whether the profile constraint explicitly pins the
// selected version — the operator's escape hatch for accepting a downgrade
// (e.g. a publisher pulled a broken release).
func isExactPin(constraint, version string) bool {
	c := strings.TrimSpace(constraint)
	return c == version || c == "="+version || c == "=="+version
}

// pinFor returns the profile's version constraint for name in scope ("" when
// the package is a resolver-chosen dependency with no profile entry).
func pinFor(p *schema.Profile, scope, name string) string {
	if ref, ok := p.Packages[scope][name]; ok {
		return ref.Version
	}
	return ""
}

// weakPolicyString renders the effective weak-deps policy for the manifest.
// WeakOff yields "" so the omitempty field is absent (off == not recorded);
// WeakOn records "on" so a rebuild reproduces the augmentation decision.
func weakPolicyString(p resolver.WeakPolicy) string {
	if p == resolver.WeakOn {
		return "on"
	}
	return ""
}

// ensureExtracted materializes the artifact's tree at dir exactly once. The
// dir is content-addressed, so an existing dir already holds the correct
// content: extraction goes to a temp sibling and lands via atomic rename, so
// a dir either exists complete or not at all, and a crash leaves only an
// ".extract-*" temp for the sweep. The previous RemoveAll+extract-in-place
// both rewrote the tree retained generations symlink through (same-version
// republish) and dangled the live generation if interrupted.
func ensureExtracted(data []byte, dir string) error {
	if _, err := os.Stat(dir); err == nil {
		// Reuse counts as activity: refresh the mtime so the sweep's grace
		// window (extractstore.DefaultMinAge) protects a dir an in-flight
		// apply is reusing, not only freshly extracted ones.
		now := time.Now()
		_ = os.Chtimes(dir, now, now)
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".extract-*")
	if err != nil {
		return err
	}
	if err := source.ExtractTarZst(bytes.NewReader(data), tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if err := os.Rename(tmp, dir); err != nil {
		_ = os.RemoveAll(tmp)
		if _, statErr := os.Stat(dir); statErr == nil {
			return nil // lost a benign race; content-addressed ⇒ identical bytes
		}
		return err
	}
	return nil
}

// openPackageFile opens the package recipe file inside pkgRoot. A tarball
// may contain polypkg.yaml or polypkg.jsonc, never both. Returns the open
// file, the filename used (for ParsePackage's format dispatch), and any
// error.
func openPackageFile(pkgRoot string) (*os.File, string, error) {
	yamlPath := filepath.Join(pkgRoot, "polypkg.yaml")
	jsoncPath := filepath.Join(pkgRoot, "polypkg.jsonc")
	yamlExists := fileExists(yamlPath)
	jsoncExists := fileExists(jsoncPath)
	switch {
	case yamlExists && jsoncExists:
		return nil, "", fmt.Errorf("ambiguous package format: both polypkg.yaml and polypkg.jsonc present in %s", pkgRoot)
	case jsoncExists:
		f, err := os.Open(filepath.Clean(jsoncPath))
		if err != nil {
			return nil, "", fmt.Errorf("open polypkg.jsonc: %w", err)
		}
		return f, "polypkg.jsonc", nil
	case yamlExists:
		f, err := os.Open(filepath.Clean(yamlPath))
		if err != nil {
			return nil, "", fmt.Errorf("open polypkg.yaml: %w", err)
		}
		return f, "polypkg.yaml", nil
	default:
		return nil, "", fmt.Errorf("no polypkg.yaml or polypkg.jsonc in %s", pkgRoot)
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
