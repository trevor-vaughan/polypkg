package ghreleasetest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// GitHubActionsIssuer is the OIDC issuer GitHub Actions certificates carry.
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

const (
	inTotoPayloadType = "application/vnd.in-toto+json"
	bundleMediaType   = "application/vnd.dev.sigstore.bundle.v0.3+json"
	slsaProvenanceV1  = "https://slsa.dev/provenance/v1"
	// releasePredicateType is GitHub's release attestation predicate.
	releasePredicateType = "https://in-toto.io/attestation/release/v0.2"

	// rekorHost names the throwaway Rekor log, as its trusted-root BaseURL
	// and its checkpoints' origin and signer name.
	rekorHost = "rekor.localhost"
	// rekorTreeID is the log's tree ID, which a Rekor v1 checkpoint origin
	// carries after the host.
	rekorTreeID = 1
)

// authority is a throwaway Sigstore built from the standard library alone: a
// Fulcio root and intermediate (so a leaf can carry any extension) and a
// Rekor log key. It writes each log entry itself, a single-leaf Merkle tree
// with its signed entry timestamp and signed checkpoint, so nothing here
// imports sigstore's testing or Rekor packages.
type authority struct {
	inter       *x509.Certificate
	interKey    *ecdsa.PrivateKey
	rekorKey    *ecdsa.PrivateKey
	logID       []byte // sha256 of the Rekor key's PKIX encoding, as Rekor derives it
	trustedRoot []byte
}

func newAuthority(now time.Time) (*authority, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate fulcio root key: %w", err)
	}
	rootCert, err := issueCA(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "ghreleasetest-root", Organization: []string{"polypkg test"}},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(10 * 365 * 24 * time.Hour),
	}, nil, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("issue fulcio root: %w", err)
	}
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate fulcio intermediate key: %w", err)
	}
	inter, err := issueCA(&x509.Certificate{
		Subject:     pkix.Name{CommonName: "ghreleasetest-intermediate", Organization: []string{"polypkg test"}},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(10 * 365 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("issue fulcio intermediate: %w", err)
	}
	rekorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate rekor key: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&rekorKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encode rekor key: %w", err)
	}
	logID := sha256.Sum256(spki)

	fulcio := &root.FulcioCertificateAuthority{
		Root:                rootCert,
		Intermediates:       []*x509.Certificate{inter},
		ValidityPeriodStart: now.Add(-time.Hour),
		URI:                 "https://fulcio.localhost",
	}
	rekor := map[string]*root.TransparencyLog{
		hex.EncodeToString(logID[:]): {
			BaseURL:             "https://" + rekorHost,
			ID:                  logID[:],
			ValidityPeriodStart: now.Add(-time.Hour),
			HashFunc:            crypto.SHA256,
			PublicKey:           &rekorKey.PublicKey,
			SignatureHashFunc:   crypto.SHA256,
		},
	}
	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		[]root.CertificateAuthority{fulcio}, nil, nil, rekor)
	if err != nil {
		return nil, fmt.Errorf("assemble trusted root: %w", err)
	}
	trJSON, err := tr.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal trusted root: %w", err)
	}
	return &authority{inter: inter, interKey: interKey, rekorKey: rekorKey, logID: logID[:], trustedRoot: trJSON}, nil
}

// issueCA issues a CA certificate from tmpl, signed by parentKey under
// parent, or self-signed when parent is nil.
func issueCA(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, parentKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	tmpl.SerialNumber = serial
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	tmpl.BasicConstraintsValid = true
	tmpl.IsCA = true
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// leaf issues a Fulcio-shaped certificate for a GitHub Actions run of repo
// (OWNER/REPO) at tag: the workflow URI as SAN, the Actions issuer in both
// the legacy and the DER extension, and the source repository extension.
func (a *authority) leaf(repo, tag string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}
	san, err := url.Parse(fmt.Sprintf("https://github.com/%s/.github/workflows/release.yml@refs/tags/%s", repo, tag))
	if err != nil {
		return nil, nil, fmt.Errorf("leaf SAN: %w", err)
	}
	issuerDER, err := asn1.MarshalWithParams(GitHubActionsIssuer, "utf8")
	if err != nil {
		return nil, nil, fmt.Errorf("encode issuer: %w", err)
	}
	repoDER, err := asn1.MarshalWithParams("https://github.com/"+repo, "utf8")
	if err != nil {
		return nil, nil, fmt.Errorf("encode source repository: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, nil, fmt.Errorf("leaf serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(10 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:         []*url.URL{san},
		ExtraExtensions: []pkix.Extension{
			// Fulcio still writes the legacy raw issuer next to the DER one.
			{Id: certificate.OIDIssuer, Value: []byte(GitHubActionsIssuer)}, //nolint:staticcheck // SA1019: mirrors real Fulcio leaves
			{Id: certificate.OIDIssuerV2, Value: issuerDER},
			{Id: certificate.OIDSourceRepositoryURI, Value: repoDER},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.inter, &key.PublicKey, a.interKey)
	if err != nil {
		return nil, nil, fmt.Errorf("issue leaf: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse leaf: %w", err)
	}
	return cert, key, nil
}

// provenanceStatement is an in-toto SLSA provenance statement whose one
// subject is assetName at sum.
func provenanceStatement(assetName string, sum [32]byte) ([]byte, error) {
	return json.Marshal(map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []map[string]any{{
			"name":   assetName,
			"digest": map[string]string{"sha256": hex.EncodeToString(sum[:])},
		}},
		"predicateType": slsaProvenanceV1,
		"predicate":     map[string]any{},
	})
}

// releaseStatement is a GitHub release attestation of assetName at sum in
// repo (OWNER/REPO) at tag, shaped as GitHub writes one: the release itself
// as an in-toto ResourceDescriptor with a purl uri and a commit sha1, then
// the asset by name and sha256.
func releaseStatement(repo, tag, assetName string, sum [32]byte) ([]byte, error) {
	commit := sha256.Sum256([]byte(repo + "@" + tag))
	return json.Marshal(map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []map[string]any{
			{
				"uri":    "pkg:github/" + repo + "@" + tag,
				"digest": map[string]string{"sha1": hex.EncodeToString(commit[:20])},
			},
			{
				"name":   assetName,
				"digest": map[string]string{"sha256": hex.EncodeToString(sum[:])},
			},
		},
		"predicateType": releasePredicateType,
		"predicate":     map[string]any{},
	})
}

// attest mints a v0.3 sigstore bundle over statement, DSSE-signed by a fresh
// leaf for repo at tag and logged with an inclusion proof and a signed entry
// timestamp.
func (a *authority) attest(statement []byte, repo, tag string, now time.Time) ([]byte, error) {
	leaf, key, err := a.leaf(repo, tag, now)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(dsse.PAE(inTotoPayloadType, statement))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign envelope: %w", err)
	}
	env := &dsse.Envelope{
		PayloadType: inTotoPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(statement),
		Signatures:  []dsse.Signature{{Sig: base64.StdEncoding.EncodeToString(sig)}},
	}
	entry, err := a.logEntry(leaf, env, statement, now.Unix())
	if err != nil {
		return nil, err
	}
	return json.Marshal(wireBundle{
		MediaType: bundleMediaType,
		VerificationMaterial: wireVerificationMaterial{
			Certificate: wireCertificate{RawBytes: base64.StdEncoding.EncodeToString(leaf.Raw)},
			TlogEntries: []wireTlogEntry{entry},
		},
		DsseEnvelope: env,
	})
}

// logEntry logs env as Rekor does a dsse v0.0.1 entry: the canonicalized
// body names the envelope and payload hashes and the signature with its
// certificate. The entry is the only leaf of the log's tree, so the root
// hash is the leaf hash and the inclusion proof has no hashes; the
// checkpoint and the signed entry timestamp are signed with the log key.
func (a *authority) logEntry(leaf *x509.Certificate, env *dsse.Envelope, payload []byte, integratedTime int64) (wireTlogEntry, error) {
	envJSON, err := json.Marshal(env)
	if err != nil {
		return wireTlogEntry{}, fmt.Errorf("marshal envelope: %w", err)
	}
	envHash, payloadHash := sha256.Sum256(envJSON), sha256.Sum256(payload)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	body, err := json.Marshal(map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "dsse",
		"spec": map[string]any{
			"envelopeHash": map[string]string{"algorithm": "sha256", "value": hex.EncodeToString(envHash[:])},
			"payloadHash":  map[string]string{"algorithm": "sha256", "value": hex.EncodeToString(payloadHash[:])},
			"signatures": []map[string]string{{
				"signature": env.Signatures[0].Sig,
				"verifier":  base64.StdEncoding.EncodeToString(certPEM),
			}},
		},
	})
	if err != nil {
		return wireTlogEntry{}, fmt.Errorf("marshal log entry body: %w", err)
	}

	// The signed entry timestamp signs the RFC 8785 form of this payload.
	// encoding/json writes a map with sorted keys, and none of these values
	// holds a character the two encodings escape differently.
	setPayload, err := json.Marshal(map[string]any{
		"body":           base64.StdEncoding.EncodeToString(body),
		"integratedTime": integratedTime,
		"logID":          hex.EncodeToString(a.logID),
		"logIndex":       0,
	})
	if err != nil {
		return wireTlogEntry{}, fmt.Errorf("marshal entry timestamp payload: %w", err)
	}
	set, err := a.sign(setPayload)
	if err != nil {
		return wireTlogEntry{}, fmt.Errorf("sign entry timestamp: %w", err)
	}

	rootHash := sha256.Sum256(append([]byte{0}, body...))
	note := fmt.Sprintf("%s - %d\n1\n%s\n", rekorHost, rekorTreeID, base64.StdEncoding.EncodeToString(rootHash[:]))
	noteSig, err := a.sign([]byte(note))
	if err != nil {
		return wireTlogEntry{}, fmt.Errorf("sign checkpoint: %w", err)
	}
	// A signed note's signature line carries the first four bytes of the
	// key's hash ahead of the signature; for Rekor that hash is the log ID.
	checkpoint := note + "\n— " + rekorHost + " " +
		base64.StdEncoding.EncodeToString(append(append([]byte(nil), a.logID[:4]...), noteSig...)) + "\n"

	return wireTlogEntry{
		LogIndex:         "0",
		LogID:            wireLogID{KeyID: base64.StdEncoding.EncodeToString(a.logID)},
		KindVersion:      wireKindVersion{Kind: "dsse", Version: "0.0.1"},
		IntegratedTime:   strconv.FormatInt(integratedTime, 10),
		InclusionPromise: &wireInclusionPromise{SignedEntryTimestamp: base64.StdEncoding.EncodeToString(set)},
		InclusionProof: &wireInclusionProof{
			LogIndex:   "0",
			RootHash:   base64.StdEncoding.EncodeToString(rootHash[:]),
			TreeSize:   "1",
			Checkpoint: wireCheckpoint{Envelope: checkpoint},
		},
		CanonicalizedBody: base64.StdEncoding.EncodeToString(body),
	}, nil
}

// sign is the log key's ECDSA signature over the sha256 of msg.
func (a *authority) sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, a.rekorKey, digest[:])
}

// The wire* types are the protojson shape of a v0.3 bundle, written by hand
// so the sigstore protobuf-specs and rekor modules stay indirect
// dependencies. bundle.Bundle.UnmarshalJSON parses them for real. protojson
// encodes int64 fields as JSON strings, so these do too.
type wireCertificate struct {
	RawBytes string `json:"rawBytes"`
}

type wireLogID struct {
	KeyID string `json:"keyId"`
}

type wireKindVersion struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
}

type wireCheckpoint struct {
	Envelope string `json:"envelope"`
}

type wireInclusionProof struct {
	LogIndex   string         `json:"logIndex"`
	RootHash   string         `json:"rootHash"`
	TreeSize   string         `json:"treeSize"`
	Hashes     []string       `json:"hashes,omitempty"`
	Checkpoint wireCheckpoint `json:"checkpoint"`
}

type wireInclusionPromise struct {
	SignedEntryTimestamp string `json:"signedEntryTimestamp"`
}

type wireTlogEntry struct {
	LogIndex          string                `json:"logIndex"`
	LogID             wireLogID             `json:"logId"`
	KindVersion       wireKindVersion       `json:"kindVersion"`
	IntegratedTime    string                `json:"integratedTime"`
	InclusionPromise  *wireInclusionPromise `json:"inclusionPromise,omitempty"`
	InclusionProof    *wireInclusionProof   `json:"inclusionProof,omitempty"`
	CanonicalizedBody string                `json:"canonicalizedBody"`
}

type wireVerificationMaterial struct {
	Certificate wireCertificate `json:"certificate"`
	TlogEntries []wireTlogEntry `json:"tlogEntries"`
}

type wireBundle struct {
	MediaType            string                   `json:"mediaType"`
	VerificationMaterial wireVerificationMaterial `json:"verificationMaterial"`
	DsseEnvelope         *dsse.Envelope           `json:"dsseEnvelope"`
}
