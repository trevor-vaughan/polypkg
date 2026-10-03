// Package gen mints deterministic carried-provenance fixtures for the e2e
// acceptance matrix. This file provides the builder-signed SLSA envelope
// primitive, the genuine (all-green) served-repo builder, and the G1 rogue-
// builder variant; later additions cover the remaining G2/G5/G9/G10 tampered
// acceptance rows.
package gen

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha1" //nolint:gosec // G505: sha1 is the tampered weak algorithm under test in the G4 fixtures, not a security primitive
	"crypto/sha256"
	"crypto/sha512"
	_ "embed" // for //go:embed of the committed sigstore fixtures below
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// BaseContent is the byte payload of every fixture's content/bin/app file; its
// sha256 is the SLSA subject digest the carried attestation binds.
var BaseContent = []byte("provenance fixture payload\n")

// The committed offline sigstore fixtures, embedded so the generator is
// self-contained (see testdata/README.md). bindableContent's sha256 is the
// bundle's in-toto subject digest; bindableRootJSON is the SigstoreRoot that
// verifies the bundle offline.
//
//go:embed testdata/bindable-bundle.json
var bindableBundleJSON []byte

//go:embed testdata/bindable-content.bin
var bindableContent []byte

//go:embed testdata/bindable-root.json
var bindableRootJSON []byte

// Fixed identifiers and media types shared by every minted fixture.
const (
	BuilderCurrentID = "builder-current"
	BuilderRogueID   = "builder-rogue"
	SLSAPredicate    = "https://slsa.dev/provenance/v1"
	inTotoPayload    = "application/vnd.in-toto+json"
)

// Keyset holds the deterministic keys every variant shares.
type Keyset struct {
	BuilderCurrent ed25519.PrivateKey
	BuilderRogue   ed25519.PrivateKey
}

func seededKey(b byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b
	}
	return ed25519.NewKeyFromSeed(seed)
}

// Keys returns the fixed builder keys (deterministic across runs).
func Keys() Keyset {
	return Keyset{BuilderCurrent: seededKey(0x02), BuilderRogue: seededKey(0x03)}
}

// PubB64 renders a raw ed25519 public key as the base64 the trust bundle and
// consumer allow-list store (NOT the "Ed"-prefixed minisign form).
func PubB64(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

func pae(payloadType string, body []byte) []byte {
	out := []byte("DSSEv1 ")
	out = append(out, strconv.Itoa(len(payloadType))...)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = append(out, strconv.Itoa(len(body))...)
	out = append(out, ' ')
	return append(out, body...)
}

// MintSLSA builds a DSSE envelope wrapping a SLSA v1.0 Statement whose single
// subject (advisory name subjectName) carries sha256hex, signed under keyID by
// priv over the DSSE PAE.
func MintSLSA(subjectName, sha256hex, keyID string, priv ed25519.PrivateKey) []byte {
	return mintSLSAWithDigest(subjectName, map[string]string{"sha256": sha256hex}, keyID, priv)
}

// mintSLSAWithDigest is MintSLSA generalized to an arbitrary subject digest set
// (algorithm name -> bare hex), so G4 fixtures can mint envelopes carrying
// multiple digests, a forbidden weak algorithm, or an uncomputable one. It signs
// the same in-toto SLSA v1.0 statement shape MintSLSA does.
func mintSLSAWithDigest(subjectName string, digest map[string]string, keyID string, priv ed25519.PrivateKey) []byte {
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"name": subjectName, "digest": digest}},
		"predicateType": SLSAPredicate,
		"predicate": map[string]any{
			"buildDefinition": map[string]any{"buildType": "https://example.com/build"},
			"runDetails": map[string]any{
				"builder":  map[string]any{"id": keyID},
				"metadata": map[string]any{"finishedOn": "2020-06-01T00:00:00Z"},
			},
		},
	}
	body, _ := json.Marshal(st)
	sig := ed25519.Sign(priv, pae(inTotoPayload, body))
	env := map[string]any{
		"payloadType": inTotoPayload,
		"payload":     base64.StdEncoding.EncodeToString(body),
		"signatures":  []map[string]string{{"keyid": keyID, "sig": base64.StdEncoding.EncodeToString(sig)}},
	}
	b, _ := json.Marshal(env)
	return b
}

// G4MismatchDigest is a subject digest whose sha256 matches BaseContent but whose
// sha512 is the hash of DIFFERENT bytes — the "all-overlap-must-agree" tamper
// (spec §11 G4): MatchSubjectDigests recomputes both and rejects on the sha512
// disagreement despite the matching sha256.
func G4MismatchDigest() map[string]string {
	sum256 := sha256.Sum256(BaseContent)
	sum512 := sha512.Sum512(bytes.Join([][]byte{BaseContent, otherContentSuffix}, nil))
	return map[string]string{
		"sha256": hex.EncodeToString(sum256[:]),
		"sha512": hex.EncodeToString(sum512[:]),
	}
}

// G4Sha1OnlyDigest is a subject offering ONLY sha1 — a forbidden weak algorithm
// MatchSubjectDigests rejects on mere presence (spec §11 G4 downgrade vector).
func G4Sha1OnlyDigest() map[string]string {
	sum := sha1.Sum(BaseContent) //nolint:gosec // G401: sha1 is the tampered weak algorithm under test, not a security primitive
	return map[string]string{"sha1": hex.EncodeToString(sum[:])}
}

// g4UnknownAlgo is a digest algorithm polypkg can neither recompute (absent from
// attest.digestStrength) nor forbids — a subject offering ONLY it has nothing at
// or above the sha256 floor and is unbindable (spec §11 G4 no-overlap).
const g4UnknownAlgo = "sha3-512"

// G4NoOverlapDigest is a subject offering only the uncomputable g4UnknownAlgo.
// The hex value is never recomputed, so a fixed placeholder of the right length
// (sha3-512 => 64 bytes) suffices.
func G4NoOverlapDigest() map[string]string {
	return map[string]string{g4UnknownAlgo: strings.Repeat("00", 64)}
}

// BuildG4MultiAlgo builds a genuine served repo tree whose carried SLSA subject
// offers BOTH sha256 and sha512 of content/bin/app (=BaseContent). Both agree
// with the installed bytes, so it binds at pack AND install time and reaches
// builder-verified — the G4 positive/selection half proving multi-algo
// agreement is accepted (spec §11 G4). Signed by BuilderCurrentID, registered
// in the anchor-signed trust bundle exactly like BuildGenuine.
func BuildG4MultiAlgo(dir string) (Tree, error) {
	keys := Keys()
	sum256 := sha256.Sum256(BaseContent)
	sum512 := sha512.Sum512(BaseContent)
	digest := map[string]string{
		"sha256": hex.EncodeToString(sum256[:]),
		"sha512": hex.EncodeToString(sum512[:]),
	}
	env := mintSLSAWithDigest("bin/app", digest, BuilderCurrentID, keys.BuilderCurrent)
	bundleKeys := []schema.BuilderKey{{
		KeyID:     BuilderCurrentID,
		PublicKey: PubB64(keys.BuilderCurrent),
		Algo:      "ed25519",
		ValidFrom: genuineKeyValidFrom,
	}}
	return buildTree(dir, env, bundleKeys, PubB64(keys.BuilderCurrent), nil)
}

// buildSwappedSLSA builds a genuine served repo tree (BuildGenuine), then
// replaces its carried SLSA pool blob with badEnv — an envelope that defeats
// install-time verification (a digest that binds nothing, a forbidden-weak
// digest set, a mismatched second algorithm, or a duplicate-JSON-key splice) —
// re-signing the swapped blob's transport signature under the fixed anchor
// keypair so the consumer's refusal is attributable to the install-time check,
// not a transport-signature error. Each such envelope fails pack-time
// bindCarried, so it can only be introduced by tampering an already-published
// tree. The shared post-publish envelope-swap primitive behind the G4 refusals,
// the G5 digest-mismatch, and the G10 duplicate-key vectors.
func buildSwappedSLSA(dir string, badEnv []byte) (Tree, error) {
	tree, err := BuildGenuine(dir)
	if err != nil {
		return Tree{}, err
	}
	slsaRef, err := findAttestationRef(tree.PublicDir, func(ref schema.AttestationRef) bool {
		return ref.PredicateType == SLSAPredicate && ref.Kind == schema.KindCarriedOpaque
	})
	if err != nil {
		return Tree{}, fmt.Errorf("locate carried SLSA attestation ref to swap: %w", err)
	}
	anchor, err := anchorKeypair()
	if err != nil {
		return Tree{}, fmt.Errorf("build anchor keypair: %w", err)
	}
	if err := swapPoolBlob(tree.PublicDir, slsaRef, badEnv, anchor); err != nil {
		return Tree{}, fmt.Errorf("swap SLSA pool blob for tampered envelope: %w", err)
	}
	return tree, nil
}

// BuildG4MismatchAlgo builds a genuine tree then swaps in a carried SLSA whose
// subject sha256 matches content/bin/app but whose sha512 is the hash of other
// bytes (G4MismatchDigest) — the "all-overlap-must-agree" refusal (spec §11 G4).
func BuildG4MismatchAlgo(dir string) (Tree, error) {
	keys := Keys()
	env := mintSLSAWithDigest("bin/app", G4MismatchDigest(), BuilderCurrentID, keys.BuilderCurrent)
	return buildSwappedSLSA(dir, env)
}

// BuildG4Sha1Only builds a genuine tree then swaps in a carried SLSA whose
// subject offers ONLY sha1 (G4Sha1OnlyDigest) — a forbidden weak algorithm
// MatchSubjectDigests rejects on presence (spec §11 G4 downgrade vector).
func BuildG4Sha1Only(dir string) (Tree, error) {
	keys := Keys()
	env := mintSLSAWithDigest("bin/app", G4Sha1OnlyDigest(), BuilderCurrentID, keys.BuilderCurrent)
	return buildSwappedSLSA(dir, env)
}

// BuildG4NoOverlap builds a genuine tree then swaps in a carried SLSA whose
// subject offers ONLY an uncomputable algorithm (G4NoOverlapDigest, sha3-512) —
// nothing at or above the sha256 floor, so it is unbindable (spec §11 G4
// no-overlap).
func BuildG4NoOverlap(dir string) (Tree, error) {
	keys := Keys()
	env := mintSLSAWithDigest("bin/app", G4NoOverlapDigest(), BuilderCurrentID, keys.BuilderCurrent)
	return buildSwappedSLSA(dir, env)
}

// Fixed identifiers for the genuine served-repo fixture.
const (
	genuinePackageName    = "provpkg"
	genuinePackageVersion = "1.0.0"
	genuineSourceName     = "prov"
	genuineTrustSerial    = 1
	genuineBundleExpires  = "2099-01-01T00:00:00Z"
	genuineKeyValidFrom   = "2000-01-01T00:00:00Z"
)

// anchorSeed and anchorKeyID fix the repo's signing (trust-anchor) keypair so
// every generated fixture tree signs under the same identity across runs.
var anchorSeed = func() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x01
	}
	return seed
}()

var anchorKeyID = [8]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8}

// buildTimestamp mirrors internal/repo/build.go's fixed trusted-comment
// timestamp. resignIndex must reproduce it exactly: the consumer verifies the
// index signature over the raw re-marshaled bytes with THIS trusted comment,
// not a re-derived one.
const buildTimestamp = "1970-01-01T00:00:00Z"

// anchorKeypair reconstructs the fixed trust-anchor keypair every generated
// fixture tree is signed under (see anchorSeed/anchorKeyID above). Tampered
// variants that mutate an already-built tree (G2, and later G7/G9/G10) need
// this to re-sign index.json after editing it; buildTree uses it too, so
// there is exactly one place the anchor identity is derived.
func anchorKeypair() (*repo.Keypair, error) {
	return repo.KeypairFromSeed(anchorSeed, anchorKeyID)
}

// Tree locates a generated served repo tree for the consumer to read.
type Tree struct {
	PublicDir   string // <dir>/public — the served root (has index.json, trust_root.pub, ...)
	TrustRoot   string // <PublicDir>/trust_root.pub
	AllowKeyB64 string // base64 raw ed25519 pubkey of the signing builder (for builders.allow)
}

// BuildGenuine builds, into dir, a real signed polypkg served repo tree (a
// single package, provpkg 1.0.0, content/bin/app = BaseContent) carrying a
// builder-signed SLSA attestation minted under BuilderCurrentID, plus a signed
// trust bundle registering that builder key. The repo itself is signed by a
// fixed anchor keypair (not BuilderCurrent) so the served tree's trust root is
// deterministic across runs. dir/public is the served root; the signing key
// material is written outside it.
func BuildGenuine(dir string) (Tree, error) {
	keys := Keys()
	sum := sha256.Sum256(BaseContent)
	env := MintSLSA("bin/app", hex.EncodeToString(sum[:]), BuilderCurrentID, keys.BuilderCurrent)
	bundleKeys := []schema.BuilderKey{{
		KeyID:     BuilderCurrentID,
		PublicKey: PubB64(keys.BuilderCurrent),
		Algo:      "ed25519",
		ValidFrom: genuineKeyValidFrom,
	}}
	return buildTree(dir, env, bundleKeys, PubB64(keys.BuilderCurrent), nil)
}

// BuildG1Rogue builds a served repo tree identical to BuildGenuine except the
// carried SLSA attestation is minted and signed by BuilderRogueID — a
// publisher-minted key the same publisher also registers in the (still
// anchor-signed) trust bundle alongside builder-current. That registration
// lets the rogue key resolve to the builder-verified TIER genuinely (spec
// §11 G1): the fixture is not a forged signature or an unregistered key, so
// the only remaining defense is the consumer's independent builders.allow
// anchor. Tree.AllowKeyB64 is the CURRENT key (what a legitimate consumer
// would allow), NOT the rogue signer, so a caller that innocently allow-lists
// it is exercising the G1 refusal, not accidentally trusting the rogue key.
func BuildG1Rogue(dir string) (Tree, error) {
	keys := Keys()
	sum := sha256.Sum256(BaseContent)
	env := MintSLSA("bin/app", hex.EncodeToString(sum[:]), BuilderRogueID, keys.BuilderRogue)
	bundleKeys := []schema.BuilderKey{
		{
			KeyID:     BuilderCurrentID,
			PublicKey: PubB64(keys.BuilderCurrent),
			Algo:      "ed25519",
			ValidFrom: genuineKeyValidFrom,
		},
		{
			KeyID:     BuilderRogueID,
			PublicKey: PubB64(keys.BuilderRogue),
			Algo:      "ed25519",
			ValidFrom: genuineKeyValidFrom,
		},
	}
	return buildTree(dir, env, bundleKeys, PubB64(keys.BuilderCurrent), nil)
}

// parseSigstoreRoot unmarshals the embedded bindable-root.json into the
// schema.SigstoreRoot a sigstore fixture publishes in its served trust bundle.
func parseSigstoreRoot() (schema.SigstoreRoot, error) {
	var sroot schema.SigstoreRoot
	if err := json.Unmarshal(bindableRootJSON, &sroot); err != nil {
		return schema.SigstoreRoot{}, fmt.Errorf("parse embedded bindable-root.json: %w", err)
	}
	return sroot, nil
}

// buildSigstoreTree builds a served repo tree carrying an offline sigstore
// bundle instead of a builder-signed SLSA envelope: content/bin/app = content
// (whose sha256 the bundle's in-toto subject covers), attestations/sigstore.json
// = bundleJSON (a dev.sigstore.bundle, bound by digest at pack time via
// bindCarried -> ExtractCarriedSubjects), and a signed trust bundle publishing
// sroot in sigstore_roots (the offline verification anchor, NOT a builder key).
// The repo is signed by the fixed anchor keypair so the served trust root is
// deterministic. It parallels buildTree; see the DRY note in the plan header.
// dir/public is the served root; key material is written outside it. The
// returned Tree.AllowKeyB64 is empty — sigstore governance is by Fulcio identity,
// not a builder allow-list.
func buildSigstoreTree(dir string, content, bundleJSON []byte, sroot schema.SigstoreRoot) (Tree, error) {
	pkgDir := filepath.Join(dir, "pkgs", genuinePackageName)
	if err := os.MkdirAll(filepath.Join(pkgDir, "content", "bin"), 0o750); err != nil {
		return Tree{}, fmt.Errorf("create package content dir: %w", err)
	}
	manifestBody := fmt.Sprintf("schema: polypkg.package/v1\nname: %s\nversion: %s\nactions: []\n",
		genuinePackageName, genuinePackageVersion)
	if err := os.WriteFile(filepath.Join(pkgDir, "polypkg.yaml"), []byte(manifestBody), 0o600); err != nil {
		return Tree{}, fmt.Errorf("write package manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "content", "bin", "app"), content, 0o600); err != nil {
		return Tree{}, fmt.Errorf("write package content: %w", err)
	}

	attDir := filepath.Join(pkgDir, "attestations")
	if err := os.MkdirAll(attDir, 0o750); err != nil {
		return Tree{}, fmt.Errorf("create attestations dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(attDir, "sigstore.json"), bundleJSON, 0o600); err != nil {
		return Tree{}, fmt.Errorf("write carried sigstore bundle: %w", err)
	}

	anchor, err := anchorKeypair()
	if err != nil {
		return Tree{}, fmt.Errorf("build anchor keypair: %w", err)
	}
	// keyDir holds the encrypted signing key at rest in a temp dir OUTSIDE the
	// fixture tree: an absolute path repo build cannot re-resolve/double (so a
	// relative output dir works), and the served fixture tree never contains key
	// material. The key is build-time-only (the consumer verifies trust_root.pub;
	// tamper builders re-sign via the deterministic anchorKeypair()), so it is
	// removed after Build. 0700 matches internal/repo/scaffold.go's KeyDir.
	keyDir, err := os.MkdirTemp("", "polypkg-fixture-key-*")
	if err != nil {
		return Tree{}, fmt.Errorf("create key dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(keyDir) }()
	keyPath := filepath.Join(keyDir, "repo.key")
	if err := repo.SaveKey(keyPath, anchor, "pw", repo.KDFScrypt); err != nil {
		return Tree{}, fmt.Errorf("save anchor key: %w", err)
	}

	manifest := "schema: polypkg.repo/v1\nsource: " + genuineSourceName + "\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  " + genuinePackageName + ":\n    - source: ./pkgs/" + genuinePackageName + "\n"
	mPath := filepath.Join(dir, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o600); err != nil {
		return Tree{}, fmt.Errorf("write repo manifest: %w", err)
	}

	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		return Tree{}, fmt.Errorf("new repo builder: %w", err)
	}
	if _, err := b.Build(repo.BuildOptions{}); err != nil {
		return Tree{}, fmt.Errorf("build repo: %w", err)
	}

	outputDir := filepath.Join(dir, "public")
	bundle := schema.TrustBundle{
		Schema:        "polypkg.trust-bundle/v1",
		Source:        genuineSourceName,
		Serial:        genuineTrustSerial,
		Expires:       genuineBundleExpires,
		SigstoreRoots: []schema.SigstoreRoot{sroot},
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		return Tree{}, fmt.Errorf("marshal trust bundle: %w", err)
	}
	sig := anchor.SignTrustBundle(genuineTrustSerial, raw)
	//nolint:gosec // G306: trust-bundle.json is served over HTTP alongside the rest of dir/public; 0644 matches internal/repo/build.go's published-artifact convention
	if err := os.WriteFile(filepath.Join(outputDir, "trust-bundle.json"), raw, 0o644); err != nil {
		return Tree{}, fmt.Errorf("write trust bundle: %w", err)
	}
	//nolint:gosec // G306: trust-bundle.json.minisig is served over HTTP alongside the rest of dir/public; 0644 matches internal/repo/build.go's published-artifact convention
	if err := os.WriteFile(filepath.Join(outputDir, "trust-bundle.json.minisig"), []byte(sig), 0o644); err != nil {
		return Tree{}, fmt.Errorf("write trust bundle signature: %w", err)
	}

	return Tree{
		PublicDir:   outputDir,
		TrustRoot:   filepath.Join(outputDir, "trust_root.pub"),
		AllowKeyB64: "",
	}, nil
}

// BuildG6SigstoreGenuine builds a served repo tree carrying the genuine embedded
// offline sigstore bundle, publishing its SigstoreRoot in the trust bundle. The
// bundle verifies offline, so the consumer records CarriedTierVerifiedOffline
// with the Fulcio SAN/issuer and installs under require:[SLSA] — the G6
// positive control (spec §11).
func BuildG6SigstoreGenuine(dir string) (Tree, error) {
	sroot, err := parseSigstoreRoot()
	if err != nil {
		return Tree{}, err
	}
	return buildSigstoreTree(dir, bindableContent, bindableBundleJSON, sroot)
}

// stripInclusionProof removes verificationMaterial.tlogEntries[].inclusionProof
// from a dev.sigstore.bundle, producing the G6 tamper: sigstore-go's strict
// bundle parse then rejects the bundle (a v0.2+ bundle requires an inclusion
// proof), so install-time VerifySigstoreBundle fails and the tier stays
// verified-transport-only. It does NOT touch mediaType, the DSSE envelope, or
// the tlog entry's integratedTime, so attest.InspectCarried's lenient probe
// still classifies the result as a sigstore-bundle with a known build time (it
// reaches the sigstore tier path and binds by digest). It asserts at least one
// inclusion proof was actually removed so a future fixture regeneration that
// changes the bundle shape cannot silently turn this into a no-op tamper.
func stripInclusionProof(bundleJSON []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(bundleJSON, &doc); err != nil {
		return nil, fmt.Errorf("parse sigstore bundle to strip inclusion proof: %w", err)
	}
	vm, ok := doc["verificationMaterial"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("sigstore bundle has no verificationMaterial object")
	}
	entries, ok := vm["tlogEntries"].([]any)
	if !ok || len(entries) == 0 {
		return nil, fmt.Errorf("sigstore bundle has no tlogEntries to strip")
	}
	stripped := 0
	for _, e := range entries {
		em, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("tlog entry is not a JSON object")
		}
		if _, has := em["inclusionProof"]; has {
			delete(em, "inclusionProof")
			stripped++
		}
	}
	if stripped == 0 {
		return nil, fmt.Errorf("no inclusionProof found to strip (bundle shape changed?)")
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("re-marshal stripped sigstore bundle: %w", err)
	}
	return out, nil
}

// BuildG6NoInclusionProof builds a served repo tree carrying the embedded offline
// sigstore bundle with its transparency-log inclusion proof stripped
// (stripInclusionProof), publishing the genuine SigstoreRoot. The bundle still
// binds by digest at pack time and still classifies as a sigstore-bundle, but it
// can no longer verify offline, so the consumer fails closed to
// verified-transport-only: it installs under DEFAULT (a downgrade) and refuses
// under require:[SLSA] (spec §11 G6). No post-publish swap is needed — the
// stripped bundle binds and installs on its own.
func BuildG6NoInclusionProof(dir string) (Tree, error) {
	stripped, err := stripInclusionProof(bindableBundleJSON)
	if err != nil {
		return Tree{}, fmt.Errorf("strip inclusion proof for G6: %w", err)
	}
	sroot, err := parseSigstoreRoot()
	if err != nil {
		return Tree{}, err
	}
	return buildSigstoreTree(dir, bindableContent, stripped, sroot)
}

// buildTree is the shared served-repo builder behind BuildGenuine,
// BuildG1Rogue, and BuildG5Relabel: a single package (provpkg 1.0.0,
// content/bin/app = BaseContent, plus any extraContent files) carrying
// slsaEnv as its attestation, plus a signed trust bundle registering
// bundleKeys. extraContent maps additional content-relative paths (forward
// slash, e.g. "bin/other") to their bytes; nil/empty for the plain single-file
// layout. The repo is signed by a fixed anchor keypair (not any builder key)
// so the served tree's trust root is deterministic across runs. dir/public is
// the served root; the signing key material is written outside it.
// allowKeyB64 becomes the returned Tree's AllowKeyB64 — the key a legitimate
// consumer of this variant would allow-list.
func buildTree(dir string, slsaEnv []byte, bundleKeys []schema.BuilderKey, allowKeyB64 string, extraContent map[string][]byte) (Tree, error) {
	pkgDir := filepath.Join(dir, "pkgs", genuinePackageName)
	if err := os.MkdirAll(filepath.Join(pkgDir, "content", "bin"), 0o750); err != nil {
		return Tree{}, fmt.Errorf("create package content dir: %w", err)
	}
	manifestBody := fmt.Sprintf("schema: polypkg.package/v1\nname: %s\nversion: %s\nactions: []\n",
		genuinePackageName, genuinePackageVersion)
	if err := os.WriteFile(filepath.Join(pkgDir, "polypkg.yaml"), []byte(manifestBody), 0o600); err != nil {
		return Tree{}, fmt.Errorf("write package manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "content", "bin", "app"), BaseContent, 0o600); err != nil {
		return Tree{}, fmt.Errorf("write package content: %w", err)
	}
	for rel, body := range extraContent {
		p := filepath.Join(pkgDir, "content", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return Tree{}, fmt.Errorf("create extra content dir for %s: %w", rel, err)
		}
		if err := os.WriteFile(p, body, 0o600); err != nil {
			return Tree{}, fmt.Errorf("write extra package content %s: %w", rel, err)
		}
	}

	attDir := filepath.Join(pkgDir, "attestations")
	if err := os.MkdirAll(attDir, 0o750); err != nil {
		return Tree{}, fmt.Errorf("create attestations dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(attDir, "slsa.json"), slsaEnv, 0o600); err != nil {
		return Tree{}, fmt.Errorf("write carried SLSA attestation: %w", err)
	}

	anchor, err := anchorKeypair()
	if err != nil {
		return Tree{}, fmt.Errorf("build anchor keypair: %w", err)
	}
	// keyDir holds the encrypted signing key at rest in a temp dir OUTSIDE the
	// fixture tree: an absolute path repo build cannot re-resolve/double (so a
	// relative output dir works), and the served fixture tree never contains key
	// material. The key is build-time-only (the consumer verifies trust_root.pub;
	// tamper builders re-sign via the deterministic anchorKeypair()), so it is
	// removed after Build. 0700 matches internal/repo/scaffold.go's KeyDir.
	keyDir, err := os.MkdirTemp("", "polypkg-fixture-key-*")
	if err != nil {
		return Tree{}, fmt.Errorf("create key dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(keyDir) }()
	keyPath := filepath.Join(keyDir, "repo.key")
	if err := repo.SaveKey(keyPath, anchor, "pw", repo.KDFScrypt); err != nil {
		return Tree{}, fmt.Errorf("save anchor key: %w", err)
	}

	manifest := "schema: polypkg.repo/v1\nsource: " + genuineSourceName + "\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  " + genuinePackageName + ":\n    - source: ./pkgs/" + genuinePackageName + "\n"
	mPath := filepath.Join(dir, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o600); err != nil {
		return Tree{}, fmt.Errorf("write repo manifest: %w", err)
	}

	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		return Tree{}, fmt.Errorf("new repo builder: %w", err)
	}
	if _, err := b.Build(repo.BuildOptions{}); err != nil {
		return Tree{}, fmt.Errorf("build repo: %w", err)
	}

	outputDir := filepath.Join(dir, "public")
	bundle := schema.TrustBundle{
		Schema:      "polypkg.trust-bundle/v1",
		Source:      genuineSourceName,
		Serial:      genuineTrustSerial,
		Expires:     genuineBundleExpires,
		BuilderKeys: bundleKeys,
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		return Tree{}, fmt.Errorf("marshal trust bundle: %w", err)
	}
	sig := anchor.SignTrustBundle(genuineTrustSerial, raw)
	//nolint:gosec // G306: trust-bundle.json is served over HTTP alongside the rest of dir/public; 0644 matches internal/repo/build.go's published-artifact convention
	if err := os.WriteFile(filepath.Join(outputDir, "trust-bundle.json"), raw, 0o644); err != nil {
		return Tree{}, fmt.Errorf("write trust bundle: %w", err)
	}
	//nolint:gosec // G306: trust-bundle.json.minisig is served over HTTP alongside the rest of dir/public; 0644 matches internal/repo/build.go's published-artifact convention
	if err := os.WriteFile(filepath.Join(outputDir, "trust-bundle.json.minisig"), []byte(sig), 0o644); err != nil {
		return Tree{}, fmt.Errorf("write trust bundle signature: %w", err)
	}

	return Tree{
		PublicDir:   outputDir,
		TrustRoot:   filepath.Join(outputDir, "trust_root.pub"),
		AllowKeyB64: allowKeyB64,
	}, nil
}

// otherContentSuffix and mismatchContentSuffix distinguish the second content
// file (G5a) and the digest-mismatched envelope's phantom subject (G5b) from
// BaseContent while staying deterministic across runs.
var (
	otherContentSuffix    = []byte("-other")
	mismatchContentSuffix = []byte("X")
	// substitutedContentSuffix distinguishes the G7 post-publish substituted
	// content/bin/app bytes from BaseContent while staying deterministic.
	substitutedContentSuffix = []byte("-substituted")
)

// BuildG5Relabel builds a served repo tree carrying TWO content files —
// content/bin/app = BaseContent and content/bin/other = BaseContent +
// otherContentSuffix — whose carried SLSA attestation's advisory subject NAME
// is the MISLEADING "bin/app", but whose digest actually matches bin/other
// (spec §11 G5, relabel half). repo build (internal/repo/carried.go's
// bindCarried) binds carried subjects BY DIGEST — the name is advisory only —
// so it binds bin/other and publishes without any tampering: the built
// index's AttestationRef.SubjectScope records "content:bin/other", never the
// misleading advisory name. A consumer's install-time re-bind
// (internal/planner/planner.go's bindCarriedRefs) re-derives the identical
// digest match against the extracted tree, proving the advisory label is
// never trusted for selection at either point of the two-point binding (P6).
func BuildG5Relabel(dir string) (Tree, error) {
	keys := Keys()
	otherContent := bytes.Join([][]byte{BaseContent, otherContentSuffix}, nil)
	sum := sha256.Sum256(otherContent)
	env := MintSLSA("bin/app", hex.EncodeToString(sum[:]), BuilderCurrentID, keys.BuilderCurrent)
	bundleKeys := []schema.BuilderKey{{
		KeyID:     BuilderCurrentID,
		PublicKey: PubB64(keys.BuilderCurrent),
		Algo:      "ed25519",
		ValidFrom: genuineKeyValidFrom,
	}}
	return buildTree(dir, env, bundleKeys, PubB64(keys.BuilderCurrent), map[string][]byte{"bin/other": otherContent})
}

// BuildG5Mismatch builds a genuine served repo tree (BuildGenuine), then
// simulates a malicious mirror swapping the carried SLSA pool blob for one
// whose subject digest matches NEITHER content/bin/app nor any other packed
// file (spec §11 G5, mismatch half): repo build itself refuses to publish an
// unbound carried attestation (bindCarried errors "binds nothing polypkg
// packed"), so this fixture can only be produced by tampering an
// already-published tree via swapPoolBlob, which re-signs the swapped blob's
// transport signature under the same fixed anchor keypair. That re-sign
// matters: without it, a consumer's refusal would be a transport-signature
// error, not the install-time digest re-bind (bindCarriedRefs) this fixture
// is meant to exercise.
func BuildG5Mismatch(dir string) (Tree, error) {
	keys := Keys()
	mismatchContent := bytes.Join([][]byte{BaseContent, mismatchContentSuffix}, nil)
	sum := sha256.Sum256(mismatchContent)
	newEnv := MintSLSA("bin/app", hex.EncodeToString(sum[:]), BuilderCurrentID, keys.BuilderCurrent)
	return buildSwappedSLSA(dir, newEnv)
}

// BuildG2StripSLSA builds a genuine served repo tree (BuildGenuine), then
// simulates a malicious mirror stripping the carried SLSA attestation while
// leaving the native SARIF attestation (and everything else) intact: it
// deletes the SLSA pool blob and its detached signature, removes the
// corresponding AttestationRef from the index, and re-signs the index under
// the same fixed anchor keypair (spec §11 G2). A consumer with
// attestation.require:[slsa] must refuse (the predicate is genuinely
// absent); a consumer without that require must still install, proving the
// strip produced a valid, installable, re-signed index rather than a broken
// one.
func BuildG2StripSLSA(dir string) (Tree, error) {
	tree, err := BuildGenuine(dir)
	if err != nil {
		return Tree{}, err
	}

	slsaRef, err := findAttestationRef(tree.PublicDir, func(ref schema.AttestationRef) bool {
		return ref.PredicateType == SLSAPredicate && ref.Kind == schema.KindCarriedOpaque
	})
	if err != nil {
		return Tree{}, fmt.Errorf("locate carried SLSA attestation ref to strip: %w", err)
	}

	blobPath := filepath.Join(tree.PublicDir, slsaRef.Artifact)
	if err := os.Remove(blobPath); err != nil {
		return Tree{}, fmt.Errorf("remove SLSA pool blob %s: %w", slsaRef.Artifact, err)
	}
	if err := os.Remove(blobPath + ".minisig"); err != nil {
		return Tree{}, fmt.Errorf("remove SLSA pool blob signature %s.minisig: %w", slsaRef.Artifact, err)
	}

	strippedHash := slsaRef.ContentHash
	err = resignIndex(tree.PublicDir, func(idx *schema.Index) error {
		entries := idx.Packages[genuinePackageName]
		if len(entries) != 1 {
			return fmt.Errorf("index has %d %s entries at resign time, want 1", len(entries), genuinePackageName)
		}
		kept := entries[0].Attestations[:0]
		for _, ref := range entries[0].Attestations {
			if ref.ContentHash == strippedHash {
				continue
			}
			kept = append(kept, ref)
		}
		if len(kept) != len(entries[0].Attestations)-1 {
			return fmt.Errorf("stripping the SLSA ref removed %d entries, want exactly 1", len(entries[0].Attestations)-len(kept))
		}
		entries[0].Attestations = kept
		idx.Packages[genuinePackageName] = entries
		return nil
	})
	if err != nil {
		return Tree{}, fmt.Errorf("resign index after stripping SLSA attestation: %w", err)
	}

	return tree, nil
}

// mismatchedPredicateType is the false predicate_type BuildG9PredicateMismatch
// gives the carried SLSA attestation's index ref; any non-empty URI that
// differs from SLSAPredicate works, this one just reads as a plausible (but
// wrong) in-toto predicate.
const mismatchedPredicateType = "https://spdx.dev/Document"

// BuildG9PredicateMismatch builds a genuine served repo tree (BuildGenuine),
// then simulates a malicious mirror falsifying the index's claim about the
// carried SLSA attestation's predicate type: the signed DSSE envelope and its
// pool blob are left byte-for-byte untouched (still a genuine, builder-signed
// SLSA v1.0 statement), but the index.json AttestationRef's predicate_type is
// rewritten to a different, unrelated URI and the index is re-signed under
// the same fixed anchor keypair (spec §11 G9 / §10.3 F2). Because the index
// itself still verifies, this is tampering-class rather than a missing-
// predicate gap: the consumer's bindCarriedRefs cross-check
// (internal/planner/planner.go) treats the signed payload's predicateType as
// authoritative and hard-refuses when a positively declared index ref
// disagrees with it — under the DEFAULT policy, with no require and no
// builders.allow needed.
func BuildG9PredicateMismatch(dir string) (Tree, error) {
	tree, err := BuildGenuine(dir)
	if err != nil {
		return Tree{}, err
	}

	slsaRef, err := findAttestationRef(tree.PublicDir, func(ref schema.AttestationRef) bool {
		return ref.PredicateType == SLSAPredicate && ref.Kind == schema.KindCarriedOpaque
	})
	if err != nil {
		return Tree{}, fmt.Errorf("locate carried SLSA attestation ref to falsify: %w", err)
	}

	err = resignIndex(tree.PublicDir, func(idx *schema.Index) error {
		entries := idx.Packages[genuinePackageName]
		if len(entries) != 1 {
			return fmt.Errorf("index has %d %s entries at resign time, want 1", len(entries), genuinePackageName)
		}
		found := false
		for i := range entries[0].Attestations {
			if entries[0].Attestations[i].ContentHash != slsaRef.ContentHash {
				continue
			}
			entries[0].Attestations[i].PredicateType = mismatchedPredicateType
			found = true
			break
		}
		if !found {
			return fmt.Errorf("carried SLSA attestation ref (content hash %s) not found at resign time", slsaRef.ContentHash)
		}
		idx.Packages[genuinePackageName] = entries
		return nil
	})
	if err != nil {
		return Tree{}, fmt.Errorf("resign index after falsifying SLSA predicate type: %w", err)
	}

	return tree, nil
}

// findAttestationRef reads and parses <publicDir>/index.json and returns the
// first AttestationRef of genuinePackageName's (sole) index entry matching
// pred. Used by tampered-fixture builders to locate the ref/pool-blob they
// are about to strip or corrupt before re-signing. Every fixture this
// generator builds is the single genuinePackageName package, so this takes
// no package-name parameter (golangci-lint's unparam catches a parameter no
// caller ever varies).
func findAttestationRef(publicDir string, pred func(schema.AttestationRef) bool) (schema.AttestationRef, error) {
	idx, err := readIndex(publicDir)
	if err != nil {
		return schema.AttestationRef{}, err
	}
	entries, ok := idx.Packages[genuinePackageName]
	if !ok || len(entries) != 1 {
		return schema.AttestationRef{}, fmt.Errorf("index has %d %q entries, want 1", len(entries), genuinePackageName)
	}
	for _, ref := range entries[0].Attestations {
		if pred(ref) {
			return ref, nil
		}
	}
	return schema.AttestationRef{}, fmt.Errorf("no matching attestation ref found for package %q", genuinePackageName)
}

// readIndex reads and parses <publicDir>/index.json.
func readIndex(publicDir string) (*schema.Index, error) {
	raw, err := os.ReadFile(filepath.Join(publicDir, "index.json")) //nolint:gosec // G304: publicDir is this test-fixture generator's own output tree, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("read index.json: %w", err)
	}
	idx, err := schema.ParseIndex(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse index.json: %w", err)
	}
	return idx, nil
}

// trustSerial reads the monotonic serial published in <publicDir>/trust.json.
// resignIndex needs it to reproduce the exact trusted-comment SignIndex binds
// (serial + buildTimestamp); it is NOT bumped by a re-sign — a mirror-side
// tamper does not republish a new trust document, so the serial the consumer
// already recorded for this source stays valid.
func trustSerial(publicDir string) (uint64, error) {
	raw, err := os.ReadFile(filepath.Join(publicDir, "trust.json")) //nolint:gosec // G304: publicDir is this test-fixture generator's own output tree, not untrusted input
	if err != nil {
		return 0, fmt.Errorf("read trust.json: %w", err)
	}
	td, err := schema.ParseTrustDoc(bytes.NewReader(raw))
	if err != nil {
		return 0, fmt.Errorf("parse trust.json: %w", err)
	}
	return td.Serial, nil
}

// resignIndex reads <publicDir>/index.json, applies mutate to the parsed
// Index, then re-marshals and re-signs it under the fixed anchor keypair so
// the tampered index still carries a valid detached signature — the shared
// primitive every tampered-index fixture (G2 and later G7/G9/G10) builds on.
// It reproduces the producer's exact signing inputs (internal/repo/build.go):
// plain json.Marshal (no re-canonicalization) and the fixed buildTimestamp
// trusted-comment, over the published serial from trust.json. Overwrites both
// index.json and index.json.minisig in place.
func resignIndex(publicDir string, mutate func(*schema.Index) error) error {
	idx, err := readIndex(publicDir)
	if err != nil {
		return err
	}
	if err := mutate(idx); err != nil {
		return fmt.Errorf("mutate index: %w", err)
	}

	newBytes, err := json.Marshal(idx)
	if err != nil {
		return fmt.Errorf("marshal mutated index: %w", err)
	}

	serial, err := trustSerial(publicDir)
	if err != nil {
		return fmt.Errorf("read published serial: %w", err)
	}

	anchor, err := anchorKeypair()
	if err != nil {
		return fmt.Errorf("rebuild anchor keypair: %w", err)
	}
	sig := anchor.SignIndex(serial, buildTimestamp, newBytes)

	idxPath := filepath.Join(publicDir, "index.json")
	//nolint:gosec // G306: index.json is served over HTTP alongside the rest of publicDir; 0644 matches internal/repo/build.go's published-artifact convention
	if err := os.WriteFile(idxPath, newBytes, 0o644); err != nil {
		return fmt.Errorf("overwrite index.json: %w", err)
	}
	//nolint:gosec // G306: index.json.minisig is served over HTTP alongside the rest of publicDir; 0644 matches internal/repo/build.go's published-artifact convention
	if err := os.WriteFile(idxPath+".minisig", []byte(sig), 0o644); err != nil {
		return fmt.Errorf("overwrite index.json.minisig: %w", err)
	}
	return nil
}

// swapPoolBlob replaces the pool blob ref points at with newBytes: it writes
// the new content-addressed blob under pool/ (the same
// "pool/<hex-of-blake3>.att.json" scheme internal/repo/build.go publishes
// under), signs it under anchor exactly as repo.Builder does at publish time
// (internal/repo/emit.go's SignAttestation call binds name/version/hash in the
// trusted comment — the consumer's verifyTransport checks that binding when it
// fetches the attestation), deletes the OLD blob and its detached signature,
// and re-signs index.json (via resignIndex) so every AttestationRef pointing
// at the old content hash is retargeted to the new Artifact/ContentHash. This
// is the shared pool-blob-swap primitive every fixture that tampers an
// already-published attestation blob builds on (G5b here, and later G10's
// duplicate-JSON-key envelope): skipping step 2's re-sign would turn any
// consumer-side refusal into a transport-signature error instead of the
// binding/parsing failure the swap is meant to exercise.
func swapPoolBlob(publicDir string, ref schema.AttestationRef, newBytes []byte, anchor *repo.Keypair) error {
	newHash := repo.ContentHash(newBytes)
	newArtifact := "pool/" + strings.TrimPrefix(newHash, "blake3:") + ".att.json"

	newPath := filepath.Join(publicDir, newArtifact)
	//nolint:gosec // G306: pool blobs are served over HTTP alongside the rest of publicDir; 0644 matches internal/repo/build.go's published-artifact convention
	if err := os.WriteFile(newPath, newBytes, 0o644); err != nil {
		return fmt.Errorf("write new pool blob %s: %w", newArtifact, err)
	}
	sig := anchor.SignAttestation(genuinePackageName, genuinePackageVersion, newBytes)
	//nolint:gosec // G306: pool blob signatures are served over HTTP alongside the rest of publicDir; 0644 matches internal/repo/build.go's published-artifact convention
	if err := os.WriteFile(newPath+".minisig", []byte(sig), 0o644); err != nil {
		return fmt.Errorf("write new pool blob signature %s.minisig: %w", newArtifact, err)
	}

	oldPath := filepath.Join(publicDir, ref.Artifact)
	if err := os.Remove(oldPath); err != nil {
		return fmt.Errorf("remove old pool blob %s: %w", ref.Artifact, err)
	}
	if err := os.Remove(oldPath + ".minisig"); err != nil {
		return fmt.Errorf("remove old pool blob signature %s.minisig: %w", ref.Artifact, err)
	}

	oldHash := ref.ContentHash
	err := resignIndex(publicDir, func(idx *schema.Index) error {
		found := false
		for pkgName, entries := range idx.Packages {
			for ei := range entries {
				for ai := range entries[ei].Attestations {
					if entries[ei].Attestations[ai].ContentHash != oldHash {
						continue
					}
					entries[ei].Attestations[ai].ContentHash = newHash
					entries[ei].Attestations[ai].Artifact = newArtifact
					found = true
				}
			}
			idx.Packages[pkgName] = entries
		}
		if !found {
			return fmt.Errorf("no attestation ref with content hash %s found at resign time", oldHash)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("resign index after swapping pool blob: %w", err)
	}
	return nil
}

// repackArtifact simulates a post-publish TOCTOU content substitution by an
// attacker who holds the publisher/anchor key, on an already-built genuine tree.
// It overwrites content/bin/app in the persisted source package dir
// (dir/pkgs/<pkg>) with newContent, re-packs the artifact via the SAME
// repo.PackArtifact path the producer used (so the tarball format is
// byte-faithful, not a hand-rolled approximation), recomputes its blake3 content
// hash, writes the new content-addressed pool/<hex>.tar.zst and its transport
// signature under the fixed anchor keypair, deletes the OLD artifact and its
// signature, and re-signs index.json (via resignIndex) to retarget the package
// IndexEntry's Artifact + ContentHash.
//
// It ALSO strips every anchor-signed NATIVE attestation (SARIF + polypkg-link,
// i.e. every ref that is not KindCarriedOpaque) and their pool blobs, keeping
// only the builder-signed carried SLSA. This is required because repo.Build
// emits native attestations whose in-toto subject is the artifact's blake3
// (internal/repo/emit.go:125-127,172); at install those are checked by
// verifyAttestation (internal/planner/planner.go:499-503) at verifyAttestations
// (planner.go:271) — BEFORE the carried re-bind (bindCarriedRefs, planner.go:288).
// Substituting the content changes the artifact blake3, so a surviving native
// attestation would refuse first ("attestation subject digest does not match
// artifact") and the carried re-bind — the un-forgeable, builder-signed backstop
// this fixture exists to exercise — would never run. G7's threat presupposes an
// attacker with the anchor key (retargeting the artifact requires re-signing the
// index), and those native attestations are anchor-signed, so removing them is
// within that attacker's power. The carried SLSA is builder-signed and cannot be
// forged, so it remains.
//
// After repackArtifact, the artifact transport signature (verifyArtifact) and the
// index content hash both still verify, so a consumer's refusal is attributable
// ONLY to the install-time carried-subject re-bind (bindCarriedRefs), not a
// transport, integrity, or native-attestation error. This is the artifact
// analogue of swapPoolBlob (which retargets an attestation pool blob).
func repackArtifact(dir, publicDir string, newContent []byte) error {
	idx, err := readIndex(publicDir)
	if err != nil {
		return err
	}
	entries, ok := idx.Packages[genuinePackageName]
	if !ok || len(entries) != 1 {
		return fmt.Errorf("index has %d %q entries, want 1", len(entries), genuinePackageName)
	}
	oldArt := entries[0].Artifact
	var nativeArtifacts []string
	for _, ref := range entries[0].Attestations {
		if ref.Kind != schema.KindCarriedOpaque {
			nativeArtifacts = append(nativeArtifacts, ref.Artifact)
		}
	}

	pkgDir := filepath.Join(dir, "pkgs", genuinePackageName)
	if err := os.WriteFile(filepath.Join(pkgDir, "content", "bin", "app"), newContent, 0o600); err != nil {
		return fmt.Errorf("substitute packed content/bin/app: %w", err)
	}
	artifact, _, err := repo.PackArtifact(pkgDir)
	if err != nil {
		return fmt.Errorf("re-pack substituted artifact: %w", err)
	}
	newHash := repo.ContentHash(artifact)
	newArt := "pool/" + strings.TrimPrefix(newHash, "blake3:") + ".tar.zst"

	anchor, err := anchorKeypair()
	if err != nil {
		return fmt.Errorf("build anchor keypair: %w", err)
	}

	newPath := filepath.Join(publicDir, newArt)
	//nolint:gosec // G306: pool artifacts are served over HTTP alongside the rest of publicDir; 0644 matches internal/repo/build.go's published-artifact convention
	if err := os.WriteFile(newPath, artifact, 0o644); err != nil {
		return fmt.Errorf("write substituted artifact %s: %w", newArt, err)
	}
	sig := anchor.SignArtifact(genuinePackageName, genuinePackageVersion, artifact)
	//nolint:gosec // G306: pool artifact signatures are served over HTTP alongside the rest of publicDir; 0644 matches internal/repo/build.go's published-artifact convention
	if err := os.WriteFile(newPath+".minisig", []byte(sig), 0o644); err != nil {
		return fmt.Errorf("write substituted artifact signature %s.minisig: %w", newArt, err)
	}

	oldPath := filepath.Join(publicDir, oldArt)
	if err := os.Remove(oldPath); err != nil {
		return fmt.Errorf("remove old artifact %s: %w", oldArt, err)
	}
	if err := os.Remove(oldPath + ".minisig"); err != nil {
		return fmt.Errorf("remove old artifact signature %s.minisig: %w", oldArt, err)
	}
	for _, na := range nativeArtifacts {
		naPath := filepath.Join(publicDir, na)
		if err := os.Remove(naPath); err != nil {
			return fmt.Errorf("remove stripped native attestation blob %s: %w", na, err)
		}
		if err := os.Remove(naPath + ".minisig"); err != nil {
			return fmt.Errorf("remove stripped native attestation signature %s.minisig: %w", na, err)
		}
	}

	err = resignIndex(publicDir, func(i *schema.Index) error {
		e := i.Packages[genuinePackageName]
		if len(e) != 1 {
			return fmt.Errorf("index has %d %s entries at resign time, want 1", len(e), genuinePackageName)
		}
		e[0].ContentHash = newHash
		e[0].Artifact = newArt
		kept := e[0].Attestations[:0]
		for _, ref := range e[0].Attestations {
			if ref.Kind != schema.KindCarriedOpaque {
				continue
			}
			kept = append(kept, ref)
		}
		if len(kept) != 1 {
			return fmt.Errorf("after stripping native attestations, %d refs remain, want exactly the 1 carried SLSA", len(kept))
		}
		e[0].Attestations = kept
		i.Packages[genuinePackageName] = e
		return nil
	})
	if err != nil {
		return fmt.Errorf("resign index after substituting artifact and stripping native attestations: %w", err)
	}
	return nil
}

// duplicatedPayloadTypeKey is the raw JSON key/value dupKeyEnvelope splices
// into a genuine SLSA envelope: the exact bytes MintSLSA already writes for
// "payloadType", so the splice adds a second, byte-identical top-level key
// rather than a differing one — isolating the G10 tamper to the
// parser-differential duplicate-key defect alone, not also a value mismatch
// that would additionally trip a digest-binding failure (G5's territory).
const duplicatedPayloadTypeKey = `"payloadType":"` + inTotoPayload + `",`

// dupKeyEnvelope takes a genuine DSSE envelope (its bytes exactly as MintSLSA
// produced them — same subject digest, same signature) and splices a SECOND,
// byte-identical "payloadType" key immediately after the envelope's opening
// brace, producing a syntactically valid but ambiguous JSON object with a
// repeated top-level key (spec §11 G10: a parser-differential vector — a
// lenient parser could bind different bytes than the ones the signature
// covers). json.Marshal cannot emit duplicate keys, so this must be a raw
// byte splice rather than a re-encode. It asserts the splice actually
// produced two occurrences of the key so a future envelope-layout change
// cannot silently turn this into a no-op tamper.
func dupKeyEnvelope(genuineEnv []byte) ([]byte, error) {
	idx := bytes.IndexByte(genuineEnv, '{')
	if idx == -1 {
		return nil, fmt.Errorf("dupKeyEnvelope: genuine envelope %s has no opening brace", genuineEnv)
	}

	dup := make([]byte, 0, len(genuineEnv)+len(duplicatedPayloadTypeKey))
	dup = append(dup, genuineEnv[:idx+1]...)
	dup = append(dup, duplicatedPayloadTypeKey...)
	dup = append(dup, genuineEnv[idx+1:]...)

	if n := bytes.Count(dup, []byte(`"payloadType"`)); n != 2 {
		return nil, fmt.Errorf("dupKeyEnvelope: splice produced %d %q occurrences, want 2", n, "payloadType")
	}
	return dup, nil
}

// BuildG10DupKeys builds a genuine served repo tree (BuildGenuine), then
// simulates a malicious mirror swapping the carried SLSA pool blob for one
// whose JSON is byte-identical to the genuine, builder-signed envelope except
// for a single spliced-in duplicate "payloadType" key (spec §11 G10, a
// parser-differential vector). swapPoolBlob re-signs the swapped blob's
// transport signature under the same fixed anchor keypair, so the eventual
// refusal is attributable to the duplicate-key detection alone, not a
// transport-signature or digest-binding failure — the subject digest and
// builder signature are otherwise identical to BuildGenuine's.
//
// attest.VerifyBuilderSignature's rejectDuplicateKeys refuses to guess which
// "payloadType" value the signature covers and reports the envelope
// structurally invalid; the planner's install-time cross-check
// (bindCarriedRefs, internal/planner/planner.go) treats that the same as an
// unverifiable signature and fails the binding CLOSED to
// verified-transport-only rather than hard-erroring itself — refusing an
// install on a weak tier is a separate policy decision (phase 2d). So, like
// G1/G2, this fixture alone does not refuse a DEFAULT (unrequired) install; a
// consumer that REQUIRES the SLSA predicate does refuse, because the
// degraded tier can no longer satisfy an anchored, allow-listed require
// (internal/planner/attestpolicy.go's enforceAttestationPolicy).
func BuildG10DupKeys(dir string) (Tree, error) {
	keys := Keys()
	sum := sha256.Sum256(BaseContent)
	genuineEnv := MintSLSA("bin/app", hex.EncodeToString(sum[:]), BuilderCurrentID, keys.BuilderCurrent)
	dup, err := dupKeyEnvelope(genuineEnv)
	if err != nil {
		return Tree{}, fmt.Errorf("splice duplicate JSON key into genuine envelope: %w", err)
	}
	return buildSwappedSLSA(dir, dup)
}

// BuildG7InstallRefused builds a genuine served repo tree (BuildGenuine), then
// simulates a post-publish TOCTOU content substitution by an attacker holding
// the publisher/anchor key (spec §11 G7): via repackArtifact it substitutes
// content/bin/app, re-packs the artifact, recomputes its blake3, re-signs the
// artifact transport signature, STRIPS the anchor-signed native artifact-binding
// attestations (which that attacker can remove), retargets the index's package
// artifact ref, and re-signs the index — leaving the BUILDER-signed carried SLSA
// attestation (minted over the ORIGINAL bytes, un-forgeable) as the sole
// remaining attestation. Artifact transport and index content-hash both still
// verify; only the consumer's install-time re-bind (bindCarriedRefs) refuses,
// because the SLSA subject digest no longer matches the actually-installed bytes.
// Proves the P6 two-point binding's un-forgeable carried backstop catches a
// substitution that survived transport integrity and native-attestation stripping.
func BuildG7InstallRefused(dir string) (Tree, error) {
	tree, err := BuildGenuine(dir)
	if err != nil {
		return Tree{}, err
	}
	substituted := bytes.Join([][]byte{BaseContent, substitutedContentSuffix}, nil)
	if err := repackArtifact(dir, tree.PublicDir, substituted); err != nil {
		return Tree{}, fmt.Errorf("substitute packed content for G7: %w", err)
	}
	return tree, nil
}

// BuildG7PackRefusedErr attempts to build a served tree whose carried SLSA
// subject digest covers phantom bytes (BaseContent + mismatchContentSuffix) that
// are NOT what buildTree packs (content/bin/app = BaseContent), exercising the
// PRODUCER half of the two-point binding: repo build's pack-time bindCarried
// (internal/repo/carried.go) refuses to publish a carried attestation binding
// nothing it packed. It returns that build error and never a usable tree, so the
// caller asserts the pack-time refusal. Nothing publishes, so there is no venom
// row for this half (spec §11 G7, pre-pack).
func BuildG7PackRefusedErr(dir string) error {
	keys := Keys()
	phantom := bytes.Join([][]byte{BaseContent, mismatchContentSuffix}, nil)
	sum := sha256.Sum256(phantom)
	env := MintSLSA("bin/app", hex.EncodeToString(sum[:]), BuilderCurrentID, keys.BuilderCurrent)
	bundleKeys := []schema.BuilderKey{{
		KeyID:     BuilderCurrentID,
		PublicKey: PubB64(keys.BuilderCurrent),
		Algo:      "ed25519",
		ValidFrom: genuineKeyValidFrom,
	}}
	_, err := buildTree(dir, env, bundleKeys, PubB64(keys.BuilderCurrent), nil)
	return err
}

// PlanPolicy is the per-source attestation policy PlanForTest applies.
type PlanPolicy struct {
	Require   []string // predicate types required (empty = none)
	AllowKeys []string // builder allow-list (base64 raw ed25519 pubkeys); empty = source-governance trust
}

// PlanForTest runs the consumer planner.Plan against a generated Tree under
// policy pol and returns the resolved provpkg entry's attestation state. It
// fails the test via t on any error (profile validation, fetch, verification,
// or policy refusal) so callers can assert directly on the returned state.
func PlanForTest(t testing.TB, tree Tree, pol PlanPolicy) *schema.AttestationState {
	t.Helper()

	res, err := runPlan(t.Context(), tree, pol, t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatalf("planner.Plan: %v", err)
	}
	if len(res.Manifest.Entries) != 1 {
		t.Fatalf("resolved manifest entries = %d, want 1", len(res.Manifest.Entries))
	}
	return res.Manifest.Entries[0].Attestation
}

// PlanForTestErr runs the same planner.Plan invocation as PlanForTest but
// returns the error instead of failing the calling test, so REFUSAL rows (a
// non-empty builders.allow that does not name the resolved builder key, e.g.
// G1) can assert on the error rather than a fatal abort.
func PlanForTestErr(tree Tree, pol PlanPolicy) error {
	dataHome, err := os.MkdirTemp("", "polypkg-plan-data-*")
	if err != nil {
		return fmt.Errorf("create data home: %w", err)
	}
	defer func() { _ = os.RemoveAll(dataHome) }()
	stateHome, err := os.MkdirTemp("", "polypkg-plan-state-*")
	if err != nil {
		return fmt.Errorf("create state home: %w", err)
	}
	defer func() { _ = os.RemoveAll(stateHome) }()

	_, err = runPlan(context.Background(), tree, pol, dataHome, stateHome)
	return err
}

// runPlan is the single planner.Plan invocation path shared by PlanForTest
// and PlanForTestErr: it builds the genuine-fixture profile for tree under
// policy pol and runs the consumer planner against it.
func runPlan(ctx context.Context, tree Tree, pol PlanPolicy, dataHome, stateHome string) (*planner.Result, error) {
	var srcPol *schema.SourceAttestationPolicy
	if len(pol.Require) > 0 || len(pol.AllowKeys) > 0 {
		srcPol = &schema.SourceAttestationPolicy{Require: pol.Require}
		if len(pol.AllowKeys) > 0 {
			allow := make([]schema.BuilderAllowEntry, len(pol.AllowKeys))
			for i, k := range pol.AllowKeys {
				allow[i] = schema.BuilderAllowEntry{Key: k}
			}
			srcPol.Builders = &schema.BuilderAllow{Allow: allow}
		}
	}

	profile := &schema.Profile{
		Schema: "polypkg.spec/v1",
		Name:   "genuine-fixture",
		Scopes: map[string]schema.ScopeSpec{"user": {Substrate: "store"}},
		Sources: schema.SourcesSpec{
			Order: []string{genuineSourceName},
			Sources: map[string]schema.SourceBackend{
				genuineSourceName: {
					Type:        "polypkg-native",
					URL:         "file://" + tree.PublicDir,
					TrustRoot:   tree.TrustRoot,
					Attestation: srcPol,
				},
			},
		},
		Packages: map[string]map[string]schema.PackageRef{
			"user": {genuinePackageName: {Version: ">=" + genuinePackageVersion}},
		},
	}

	return planner.Plan(ctx, profile, planner.Options{
		Scope:     "user",
		DataHome:  dataHome,
		StateHome: stateHome,
	})
}
