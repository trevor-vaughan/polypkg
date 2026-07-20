package attest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// inTotoPayloadType is the DSSE payloadType for an in-toto Statement.
const inTotoPayloadType = "application/vnd.in-toto+json"

// spdxDocumentType and cyclonedxBOMType are the in-toto predicate-type URIs for
// SPDX and CycloneDX SBOMs. A DSSE-wrapped SBOM carries one as its statement's
// predicateType; a raw (unwrapped) SBOM has no in-toto predicateType, so
// InspectCarried records the canonical URI here (the index-ref schema requires a
// non-empty predicate_type, and pack and install must record the same value for
// the G9 cross-check).
const (
	spdxDocumentType = "https://spdx.dev/Document"
	cyclonedxBOMType = "https://cyclonedx.org/bom"
)

// recognizedGenericPredicates are non-SLSA/SPDX/CycloneDX in-toto predicate types
// polypkg recognizes as legitimate supply-chain provenance and classifies as
// in-toto-generic (policy-weightable in phase 2d). URIs verified against
// in-toto.io / slsa.dev (2026-07-06). A predicate type outside this set — and
// outside the SLSA/SPDX/CycloneDX families — is in-toto-unclassified: bound and
// possibly builder-verified, but carrying no policy weight (GAP8: classification
// is (predicateType, builder), never an unknown predicate alone).
var recognizedGenericPredicates = map[string]struct{}{
	"https://in-toto.io/attestation/link/v0.3":          {},
	"https://in-toto.io/attestation/test-result/v0.1":   {},
	"https://in-toto.io/attestation/vulns/v0.2":         {},
	"https://in-toto.io/attestation/scai/v0.3":          {},
	"https://in-toto.io/attestation/runtime-trace/v0.1": {},
	"https://slsa.dev/verification_summary/v1":          {},
}

// classifyFormat maps an in-toto predicateType to the polypkg carriage format.
// SLSA provenance (any version), SPDX, and CycloneDX map to their own formats; a
// predicateType on the generic allow-list maps to in-toto-generic; anything else
// is in-toto-unclassified (recognized as in-toto, but carrying no policy weight).
func classifyFormat(predicateType string) string {
	switch {
	case strings.HasPrefix(predicateType, "https://slsa.dev/provenance/"):
		return schema.FormatSLSAProvenance
	case predicateType == spdxDocumentType:
		return schema.FormatSPDX
	case predicateType == cyclonedxBOMType:
		return schema.FormatCycloneDX
	default:
		if _, ok := recognizedGenericPredicates[predicateType]; ok {
			return schema.FormatInTotoGeneric
		}
		return schema.FormatInTotoUnclassified
	}
}

// CarriedInfo is the shallow, unverified interpretation of a carried attestation
// envelope: the inner statement's predicate type, the polypkg format it maps to,
// the in-toto subjects it covers, and — for SLSA provenance — the builder identity
// and build timestamp the install-time window gate needs. Digests here are
// advisory (the caller binds them against installed bytes, P6); the builder
// signature is verified separately (VerifyBuilderSignature). InspectCarried does
// NEITHER — it only reads.
type CarriedInfo struct {
	PredicateType string
	Format        string
	Subjects      []Subject
	// SLSABuilderID is the SLSA provenance builder id (version-aware path), or ""
	// for a non-SLSA predicate or a SLSA predicate that omits it.
	SLSABuilderID string
	// BuildTime is the SLSA build finished (or, failing that, started) timestamp;
	// it is meaningful only when BuildTimeKnown is true. A predicate carrying no
	// parseable timestamp leaves it zero so the window gate no-ops (design F1).
	BuildTime      time.Time
	BuildTimeKnown bool
}

// InspectCarried shallow-parses a carried attestation envelope — a DSSE envelope
// wrapping an in-toto Statement, or a bare in-toto Statement — into a CarriedInfo.
// It does NOT verify the DSSE/builder signature (that is VerifyBuilderSignature);
// it reads only what the caller needs to bind digests (P6) and, once the signature
// is verified, to apply the key validity-window gate. An unrecognized envelope is
// an error; a SLSA predicate it cannot fully interpret is not (it yields less
// metadata). A raw SPDX/CycloneDX SBOM (no DSSE/in-toto wrapper) is recognized
// and its subjects synthesized from its own checksums (verified-transport-only at
// most); a dev.sigstore.bundle is recognized (format sigstore-bundle) and its
// inner DSSE in-toto subjects extracted; the kernel (VerifySigstoreBundle)
// verifies it.
func InspectCarried(data []byte) (CarriedInfo, error) {
	// Probe for a DSSE envelope (payloadType + payload), a bare Statement (_type),
	// or a raw SBOM (spdxVersion / bomFormat). A permissive decode: envelopes and
	// SBOMs carry many extra fields we ignore.
	var probe struct {
		PayloadType          string          `json:"payloadType"`
		Payload              string          `json:"payload"`
		Type                 string          `json:"_type"`
		SPDXVersion          string          `json:"spdxVersion"`
		BOMFormat            string          `json:"bomFormat"`
		MediaType            string          `json:"mediaType"`
		VerificationMaterial json.RawMessage `json:"verificationMaterial"`
	}
	if jerr := json.Unmarshal(data, &probe); jerr != nil {
		return CarriedInfo{}, fmt.Errorf("parse attestation envelope: %w", jerr)
	}

	// A sigstore bundle is identified by its media type or by a top-level
	// verificationMaterial OBJECT; a null/scalar merely carrying the key is not a
	// bundle and falls through to "unrecognized" below.
	vmRaw := bytes.TrimSpace(probe.VerificationMaterial)
	sigstoreLike := strings.HasPrefix(probe.MediaType, "application/vnd.dev.sigstore.bundle") ||
		(len(vmRaw) > 0 && vmRaw[0] == '{')

	var stmtBytes []byte
	switch {
	case probe.PayloadType != "" || probe.Payload != "":
		if probe.PayloadType != inTotoPayloadType {
			return CarriedInfo{}, fmt.Errorf("carried DSSE payloadType %q is not %q", probe.PayloadType, inTotoPayloadType)
		}
		decoded, derr := base64.StdEncoding.DecodeString(probe.Payload)
		if derr != nil {
			return CarriedInfo{}, fmt.Errorf("decode carried DSSE payload: %w", derr)
		}
		stmtBytes = decoded
	case probe.Type != "":
		stmtBytes = data
	case probe.SPDXVersion != "":
		return inspectRawSPDX(data)
	case probe.BOMFormat == "CycloneDX":
		return inspectRawCycloneDX(data)
	case sigstoreLike:
		return inspectSigstoreBundle(data)
	default:
		return CarriedInfo{}, errors.New("unrecognized attestation envelope: neither a DSSE envelope, an in-toto Statement, nor a raw SPDX/CycloneDX SBOM")
	}

	st, perr := ParseStatement(stmtBytes)
	if perr != nil {
		return CarriedInfo{}, fmt.Errorf("parse carried statement: %w", perr)
	}
	info := CarriedInfo{
		PredicateType: st.PredicateType,
		Format:        classifyFormat(st.PredicateType),
		Subjects:      st.Subject,
	}
	if info.Format == schema.FormatSLSAProvenance {
		info.SLSABuilderID, info.BuildTime, info.BuildTimeKnown = interpretSLSA(st.PredicateType, st.Predicate)
	}
	return info, nil
}

// ExtractCarriedSubjects returns just the predicate type, format, and subjects of
// a carried envelope — the pack-time binding view (repo.bindCarried). It delegates
// to InspectCarried, dropping the SLSA builder/timestamp fields the publisher does
// not consume.
func ExtractCarriedSubjects(data []byte) (predicateType, format string, subjects []Subject, err error) {
	info, ierr := InspectCarried(data)
	if ierr != nil {
		return "", "", nil, ierr
	}
	return info.PredicateType, info.Format, info.Subjects, nil
}

// interpretSLSA extracts the builder id and build timestamp from a SLSA provenance
// predicate, dispatching on the version in predicateType (verified against
// slsa.dev, 2026-07-06): v1.0 nests under runDetails/buildDefinition, v0.2 is
// flat. It never errors — a predicate it cannot fully read still binds and
// verifies, it just carries less metadata: an absent or unparseable timestamp
// yields known=false (the window gate then no-ops, design F1) and an absent id
// yields "". The decode is permissive (SLSA predicates carry many ignored fields).
func interpretSLSA(predicateType string, predicate json.RawMessage) (builderID string, buildTime time.Time, known bool) {
	parse := func(ts string) {
		if ts == "" {
			return
		}
		if t, perr := time.Parse(time.RFC3339, ts); perr == nil {
			buildTime, known = t, true
		}
	}
	switch predicateType {
	case "https://slsa.dev/provenance/v1":
		var p struct {
			RunDetails struct {
				Builder struct {
					ID string `json:"id"`
				} `json:"builder"`
				Metadata struct {
					StartedOn  string `json:"startedOn"`
					FinishedOn string `json:"finishedOn"`
				} `json:"metadata"`
			} `json:"runDetails"`
		}
		if json.Unmarshal(predicate, &p) != nil {
			return "", time.Time{}, false
		}
		builderID = p.RunDetails.Builder.ID
		ts := p.RunDetails.Metadata.FinishedOn
		if ts == "" {
			ts = p.RunDetails.Metadata.StartedOn
		}
		parse(ts)
	case "https://slsa.dev/provenance/v0.2":
		var p struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
			Metadata struct {
				BuildStartedOn  string `json:"buildStartedOn"`
				BuildFinishedOn string `json:"buildFinishedOn"`
			} `json:"metadata"`
		}
		if json.Unmarshal(predicate, &p) != nil {
			return "", time.Time{}, false
		}
		builderID = p.Builder.ID
		ts := p.Metadata.BuildFinishedOn
		if ts == "" {
			ts = p.Metadata.BuildStartedOn
		}
		parse(ts)
	}
	return builderID, buildTime, known
}

// sbomAlgoAliases maps the SPDX (un-hyphenated) and CycloneDX (hyphenated)
// spellings of the digest algorithms polypkg can recompute to polypkg's internal
// lowercase names. Algorithms absent here — the broken sha1/md5 and anything
// polypkg cannot recompute (sha3-*, blake2b-*, adler32, …) — are dropped during
// synthesis: keeping only recomputable strong digests means a real SBOM's routine
// SHA1 checksum does not trip MatchSubjectDigests' forbidden-algo rejection, while
// binding still rests on a floor-level (sha256+) match.
var sbomAlgoAliases = map[string]string{
	"sha256":  "sha256",
	"sha-256": "sha256",
	"sha512":  "sha512",
	"sha-512": "sha512",
	"blake3":  "blake3",
}

// normalizeSBOMAlgo returns polypkg's internal name for an SBOM algorithm string
// (either dialect), and ok=false for an algorithm polypkg does not recompute.
func normalizeSBOMAlgo(raw string) (string, bool) {
	n, ok := sbomAlgoAliases[strings.ToLower(raw)]
	return n, ok
}

// sbomSubject builds a Subject from a digest set, or ok=false when the set is
// empty (all algorithms were dropped) — such a subject is unbindable and omitted,
// leaving the caller to refuse if nothing else binds (P6, fail closed).
func sbomSubject(name string, digests map[string]string) (Subject, bool) {
	if len(digests) == 0 {
		return Subject{}, false
	}
	return Subject{Name: name, Digest: digests}, true
}

// inspectRawSPDX synthesizes carried subjects from a raw SPDX 2.x JSON document,
// one per files[]/packages[] entry that carries a recomputable strong checksum.
// The document has no in-toto predicateType, so PredicateType is the canonical
// SPDX document URI. Digests are advisory here; the caller binds them against
// installed bytes (P6) and the tier caps at verified-transport-only (no builder
// signature).
func inspectRawSPDX(data []byte) (CarriedInfo, error) {
	type checksum struct {
		Algorithm     string `json:"algorithm"`
		ChecksumValue string `json:"checksumValue"`
	}
	var doc struct {
		Files []struct {
			Name      string     `json:"fileName"`
			Checksums []checksum `json:"checksums"`
		} `json:"files"`
		Packages []struct {
			Name      string     `json:"name"`
			Checksums []checksum `json:"checksums"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return CarriedInfo{}, fmt.Errorf("parse raw SPDX document: %w", err)
	}
	digestsOf := func(cs []checksum) map[string]string {
		d := map[string]string{}
		for _, c := range cs {
			if algo, ok := normalizeSBOMAlgo(c.Algorithm); ok {
				d[algo] = c.ChecksumValue
			}
		}
		return d
	}
	var subjects []Subject
	for _, f := range doc.Files {
		if s, ok := sbomSubject(f.Name, digestsOf(f.Checksums)); ok {
			subjects = append(subjects, s)
		}
	}
	for _, p := range doc.Packages {
		if s, ok := sbomSubject(p.Name, digestsOf(p.Checksums)); ok {
			subjects = append(subjects, s)
		}
	}
	return CarriedInfo{PredicateType: spdxDocumentType, Format: schema.FormatSPDX, Subjects: subjects}, nil
}

// cdxComponent is the recursive CycloneDX component shape polypkg reads: a name,
// its hashes, and nested sub-components.
type cdxComponent struct {
	Name   string `json:"name"`
	Hashes []struct {
		Alg     string `json:"alg"`
		Content string `json:"content"`
	} `json:"hashes"`
	Components []cdxComponent `json:"components"`
}

// inspectRawCycloneDX synthesizes carried subjects from a raw CycloneDX JSON BOM,
// one per component (the described metadata.component and every components[] entry,
// recursively) that carries a recomputable strong hash. Like inspectRawSPDX it
// records the canonical BOM URI as PredicateType and leaves the tier to cap at
// verified-transport-only.
func inspectRawCycloneDX(data []byte) (CarriedInfo, error) {
	var doc struct {
		Metadata struct {
			Component cdxComponent `json:"component"`
		} `json:"metadata"`
		Components []cdxComponent `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return CarriedInfo{}, fmt.Errorf("parse raw CycloneDX BOM: %w", err)
	}
	var subjects []Subject
	var collect func(c cdxComponent)
	collect = func(c cdxComponent) {
		digests := map[string]string{}
		for _, h := range c.Hashes {
			if algo, ok := normalizeSBOMAlgo(h.Alg); ok {
				digests[algo] = h.Content
			}
		}
		if s, ok := sbomSubject(c.Name, digests); ok {
			subjects = append(subjects, s)
		}
		for _, sub := range c.Components {
			collect(sub)
		}
	}
	collect(doc.Metadata.Component)
	for _, c := range doc.Components {
		collect(c)
	}
	return CarriedInfo{PredicateType: cyclonedxBOMType, Format: schema.FormatCycloneDX, Subjects: subjects}, nil
}

// carriedStatementTypes are the in-toto Statement `_type` layouts InspectCarried
// accepts from a sigstore bundle's inner DSSE payload: the current ITE-6 "v1"
// type, and the legacy pre-ITE-6 "v0.1" type real-world tooling still emits when
// wrapping SLSA v0.2 provenance (verified against sigstore-go's own bundled
// examples across v1.1.4/v1.2.0/v1.2.2 — all three ship "v0.1"-typed statements).
// This is deliberately more permissive than statement.go's ParseStatement, which
// enforces exactly "v1" for polypkg's own authored (always-v1) statements; a
// sigstore bundle's inner statement is third-party content InspectCarried only
// ever reads, never authors.
var carriedStatementTypes = map[string]struct{}{
	statementType:                       {},
	"https://in-toto.io/Statement/v0.1": {},
}

// parseCarriedStatement decodes and validates a third-party in-toto Statement
// exactly like ParseStatement (unknown fields rejected, at least one subject
// carrying at least one digest, non-empty predicateType), except it accepts any
// type in carriedStatementTypes instead of requiring exactly the current "v1".
func parseCarriedStatement(data []byte) (Statement, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var st Statement
	if err := dec.Decode(&st); err != nil {
		return Statement{}, fmt.Errorf("decode statement: %w", err)
	}
	if _, ok := carriedStatementTypes[st.Type]; !ok {
		return Statement{}, fmt.Errorf("statement _type %q is not a recognized in-toto Statement type", st.Type)
	}
	if len(st.Subject) == 0 {
		return Statement{}, errors.New("statement has no subject")
	}
	hasDigest := false
	for _, s := range st.Subject {
		if len(s.Digest) > 0 {
			hasDigest = true
			break
		}
	}
	if !hasDigest {
		return Statement{}, errors.New("statement has no subject digest")
	}
	if st.PredicateType == "" {
		return Statement{}, errors.New("statement has no predicateType")
	}
	return st, nil
}

// decodeProtojsonBytes decodes a proto3-JSON `bytes` field. The proto3 JSON
// specification accepts standard OR URL-safe base64, with or without padding,
// and sigstore-go's protojson parser — which the kernel uses to verify the very
// same payload — honours all four forms. Recognition must decode to the
// identical bytes the kernel verifies, so it tries each; any input valid under
// more than one form decodes to the same bytes (standard and URL-safe differ
// only in two alphabet characters that cannot co-occur in one valid string), so
// the order is immaterial to correctness. Contrast the bare-DSSE path, which
// stays standard-only: that payload is verified by polypkg's own kernel whose
// PAE also uses standard base64.
func decodeProtojsonBytes(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("payload is not valid standard or URL-safe base64")
}

// inspectSigstoreBundle shallow-reads a dev.sigstore.bundle: the inner in-toto
// Statement lives in dsseEnvelope.payload (base64), and the Rekor integrated time
// (a trust-root selection hint, re-verified by the kernel) in
// verificationMaterial.tlogEntries[0].integratedTime. It does NOT verify the
// bundle (that is VerifySigstoreBundle). Format is sigstore-bundle regardless of
// the inner predicate; a bundle without a DSSE in-toto payload has no subjects to
// bind and is rejected (fail closed).
func inspectSigstoreBundle(data []byte) (CarriedInfo, error) {
	var b struct {
		DSSEEnvelope struct {
			Payload     string `json:"payload"`
			PayloadType string `json:"payloadType"`
		} `json:"dsseEnvelope"`
		VerificationMaterial struct {
			TlogEntries []struct {
				IntegratedTime string `json:"integratedTime"`
			} `json:"tlogEntries"`
		} `json:"verificationMaterial"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return CarriedInfo{}, fmt.Errorf("parse sigstore bundle: %w", err)
	}
	if b.DSSEEnvelope.Payload == "" {
		return CarriedInfo{}, errors.New("sigstore bundle carries no DSSE in-toto envelope")
	}
	if b.DSSEEnvelope.PayloadType != "" && b.DSSEEnvelope.PayloadType != inTotoPayloadType {
		return CarriedInfo{}, fmt.Errorf("sigstore bundle dsse payloadType %q is not %q", b.DSSEEnvelope.PayloadType, inTotoPayloadType)
	}
	stmtBytes, derr := decodeProtojsonBytes(b.DSSEEnvelope.Payload)
	if derr != nil {
		return CarriedInfo{}, fmt.Errorf("decode sigstore dsse payload: %w", derr)
	}
	st, perr := parseCarriedStatement(stmtBytes)
	if perr != nil {
		return CarriedInfo{}, fmt.Errorf("parse sigstore inner statement: %w", perr)
	}
	info := CarriedInfo{
		PredicateType: st.PredicateType,
		Format:        schema.FormatSigstoreBundle,
		Subjects:      st.Subject,
	}
	if len(b.VerificationMaterial.TlogEntries) > 0 {
		if secs, cerr := strconv.ParseInt(b.VerificationMaterial.TlogEntries[0].IntegratedTime, 10, 64); cerr == nil {
			info.BuildTime, info.BuildTimeKnown = time.Unix(secs, 0).UTC(), true
		}
	}
	return info, nil
}
