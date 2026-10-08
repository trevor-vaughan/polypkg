package importer

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// githubActionsIssuer is the Fulcio OIDC issuer of GitHub Actions workflow
// identities, the only signer whose attestations an import carries.
const githubActionsIssuer = "https://token.actions.githubusercontent.com"

// inTotoPayloadType is the DSSE payload type of an in-toto statement.
const inTotoPayloadType = "application/vnd.in-toto+json"

// bundleOutcome is what an import does with one fetched attestation that did
// not refuse it.
type bundleOutcome int

const (
	// bundleKept: verified SLSA provenance of the imported repository's
	// GitHub Actions build; carried.
	bundleKept bundleOutcome = iota + 1
	// bundleDropped: verified SLSA provenance from another OIDC issuer or
	// source repository; reported as a warning.
	bundleDropped
	// bundleSkipped: not SLSA provenance (for example GitHub's release
	// attestation, signed by a CA the public-good root does not hold);
	// reported as a note, never verified.
	bundleSkipped
)

// checkBundle decides what the import does with one sigstore bundle the
// attestations API returned for the asset whose sha256 is assetSHA256.
//
// The bundle's in-toto predicate type is read first, without verification,
// by predicateTypeOf. A bundle with no readable DSSE in-toto payload or no
// predicate type is an error. Anything but SLSA provenance
// (attest.ClassifyFormat's family) is skipped unverified and unparsed, so an
// attestation kind polypkg does not carry (GitHub's release attestation,
// whose subjects carry in-toto fields the strict carry-in parser rejects)
// cannot refuse the import. SLSA provenance must then pass the strict
// carry-in parser as a sigstore bundle and verify offline against tm; one that does not verify, or verifies without
// naming the asset among its subjects, is an error: the API returned it for
// this digest, so it is a tamper signal that refuses the import. Verified
// provenance issued to another OIDC issuer, or built from a repository other
// than repoURI, is dropped. The repository is read from the Fulcio Source
// Repository URI extension, not the SAN, which names a reusable workflow's
// repository rather than the one built. why explains a drop or a skip.
func checkBundle(bundle []byte, tm root.TrustedMaterial, assetSHA256, repoURI string) (outcome bundleOutcome, why string, err error) {
	predicateType, err := predicateTypeOf(bundle)
	if err != nil {
		return 0, "", err
	}
	if attest.ClassifyFormat(predicateType) != schema.FormatSLSAProvenance {
		return bundleSkipped, fmt.Sprintf("skipped an attestation with predicate type %q; only SLSA provenance is carried", predicateType), nil
	}
	info, err := attest.InspectCarried(bundle)
	if err != nil {
		return 0, "", fmt.Errorf("its in-toto statement cannot be read: %w", err)
	}
	if info.Format != schema.FormatSigstoreBundle {
		return 0, "", fmt.Errorf("it is not a sigstore bundle (it reads as %s)", info.Format)
	}
	v, err := attest.VerifySigstoreBundle(bundle, tm)
	if err != nil {
		return 0, "", err
	}
	if !v.Verified {
		return 0, "", &verifyFailure{reason: v.FailureReason}
	}
	if !attestsDigest(v.Subjects, assetSHA256) {
		return 0, "", errors.New("it verifies, but none of its subjects is this asset's sha256")
	}
	if v.CertificateIssuer != githubActionsIssuer {
		return bundleDropped, fmt.Sprintf("dropped a provenance attestation issued to OIDC issuer %q, not GitHub Actions", v.CertificateIssuer), nil
	}
	if !asciiEqualFold(v.SourceRepositoryURI, repoURI) {
		return bundleDropped, fmt.Sprintf("dropped a provenance attestation built from %q, not %s", v.SourceRepositoryURI, repoURI), nil
	}
	return bundleKept, "", nil
}

// predicateTypeOf reads only the in-toto predicateType of a sigstore
// bundle's DSSE payload. Every other field of the bundle and the statement is
// ignored, so a statement the strict carry-in parser would reject still
// classifies. The payload is protojson bytes, which may be standard or
// URL-safe base64, padded or not. The bundle's size is already capped by
// the attestations client.
func predicateTypeOf(bundle []byte) (string, error) {
	var b struct {
		DSSEEnvelope *struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil {
		return "", fmt.Errorf("its in-toto statement cannot be read: %w", err)
	}
	if b.DSSEEnvelope == nil || b.DSSEEnvelope.Payload == "" {
		return "", errors.New("it is not a sigstore bundle carrying a DSSE envelope")
	}
	if b.DSSEEnvelope.PayloadType != inTotoPayloadType {
		return "", fmt.Errorf("its in-toto statement cannot be read: DSSE payload type %q is not %s", b.DSSEEnvelope.PayloadType, inTotoPayloadType)
	}
	var payload []byte
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if p, err := enc.DecodeString(b.DSSEEnvelope.Payload); err == nil {
			payload = p
			break
		}
	}
	if payload == nil {
		return "", errors.New("its in-toto statement cannot be read: the DSSE payload is not base64")
	}
	var st struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(payload, &st); err != nil {
		return "", fmt.Errorf("its in-toto statement cannot be read: %w", err)
	}
	if st.PredicateType == "" {
		return "", errors.New("its in-toto statement cannot be read: it names no predicate type")
	}
	return st.PredicateType, nil
}

// verifyFailure is checkBundle's error for SLSA provenance that does not
// verify against the trusted root. reason is sigstore-go's explanation, which
// can echo bundle contents, so it is quoted.
type verifyFailure struct {
	reason string
}

func (e *verifyFailure) Error() string {
	return fmt.Sprintf("does not verify against the Sigstore trusted root: %q; this indicates tampering, "+
		"or a bundle signed outside Sigstore's public-good instance (from GitHub Enterprise Server or a private repository), which polypkg cannot import",
		e.reason)
}

// asciiEqualFold reports whether a and b are equal ignoring ASCII case only,
// as GitHub compares owner and repository names. strings.EqualFold also folds
// Unicode ("ſ" matches "s", "K" (Kelvin) matches "k"), which would let a
// certificate naming a look-alike URI pass as the imported repository.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

// lowerASCII lower-cases an ASCII upper-case letter and leaves any other byte
// as it is.
func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// attestsDigest reports whether any subject carries sha256 as its sha256
// digest.
func attestsDigest(subjects []attest.Subject, sha256 string) bool {
	for _, s := range subjects {
		if strings.EqualFold(s.Digest["sha256"], sha256) {
			return true
		}
	}
	return false
}
