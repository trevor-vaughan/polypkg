package attest

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// SigstoreVerdict is the outcome of offline sigstore-bundle verification. Verified
// is true only when sigstore-go cryptographically verified the full chain (Fulcio
// cert to root, SCT when CT keys are present, Rekor inclusion proof + SET against
// the mirrored Rekor key, and the inner DSSE signature) against the supplied
// trust material. Identity is RECORDED, not gated — the SAN/issuer allow-list is
// phase 2d. Digests in Subjects are advisory; the caller binds them against
// installed bytes (P6, phase 2c-3b).
type SigstoreVerdict struct {
	Verified            bool
	CertificateIdentity string // Fulcio SAN
	CertificateIssuer   string // OIDC issuer
	// SourceRepositoryURI is the Fulcio Source Repository URI extension (OID
	// 1.3.6.1.4.1.57264.1.12): the repository whose code the signing workflow
	// built. A build that signs through a reusable workflow carries that
	// workflow's repository in the SAN, but this always names the built
	// repository. "" when the certificate does not carry it.
	SourceRepositoryURI string
	Subjects            []Subject
	IntegratedTime      time.Time
	// FailureReason is sigstore-go's explanation when Verified is false
	// because verification failed; "" otherwise. It can echo bundle
	// contents, so quote it when displaying it.
	FailureReason string
}

// SigstoreTrustedMaterial adapts polypkg's mirrored SigstoreRoot (base64-DER
// Fulcio CA chain + base64-DER Rekor/CT public keys, time-windowed) into a
// sigstore-go root.TrustedMaterial for OFFLINE verification. It contacts no
// network and loads no TUF. An empty Fulcio CA set is an error (a source that
// publishes no usable sigstore root cannot verify — the caller falls back to
// verified-transport-only, fail closed).
func SigstoreTrustedMaterial(r schema.SigstoreRoot) (root.TrustedMaterial, error) {
	start, err := time.Parse(time.RFC3339, r.ValidFrom)
	if err != nil {
		return nil, fmt.Errorf("sigstore root valid_from: %w", err)
	}
	end := time.Now().AddDate(100, 0, 0)
	if r.ValidUntil != "" {
		if end, err = time.Parse(time.RFC3339, r.ValidUntil); err != nil {
			return nil, fmt.Errorf("sigstore root valid_until: %w", err)
		}
	}

	certs, err := parseDERCerts(r.FulcioCA)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("sigstore root has no Fulcio CA certificates")
	}
	// Anchor on the self-signed root, not chain position: FulcioCA is documented
	// as "root + intermediates", but relying on ordering silently mis-anchors the
	// trust pool if a mirror emits the chain in another order. Identify the root
	// by self-signature (subject == issuer and it verifies against itself); every
	// other cert is an intermediate.
	var rootCert *x509.Certificate
	var intermediates []*x509.Certificate
	for _, c := range certs {
		if bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil {
			if rootCert != nil {
				return nil, fmt.Errorf("sigstore root has multiple self-signed Fulcio certificates")
			}
			rootCert = c
			continue
		}
		intermediates = append(intermediates, c)
	}
	if rootCert == nil {
		return nil, fmt.Errorf("sigstore root has no self-signed Fulcio root certificate")
	}
	fca := &root.FulcioCertificateAuthority{
		Root:                rootCert,
		Intermediates:       intermediates,
		ValidityPeriodStart: start,
		ValidityPeriodEnd:   end,
	}

	rekorLogs, err := transparencyLogs(r.RekorKeys, start, end)
	if err != nil {
		return nil, fmt.Errorf("rekor keys: %w", err)
	}
	ctLogs, err := transparencyLogs(r.CTLogKeys, start, end)
	if err != nil {
		return nil, fmt.Errorf("ctlog keys: %w", err)
	}

	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		[]root.CertificateAuthority{fca}, ctLogs, nil, rekorLogs)
	if err != nil {
		return nil, fmt.Errorf("assemble trusted root: %w", err)
	}
	return tr, nil
}

// transparencyLogs builds Rekor/CT log verifiers keyed by hex log id (SHA-256 of
// the DER SubjectPublicKeyInfo), all sha256, valid over [start,end]. The [start,end]
// window is the SigstoreRoot's own validity window: polypkg mirrors the CA and log
// keys together as one time-windowed trust unit, so there are no per-key windows.
func transparencyLogs(b64Keys []string, start, end time.Time) (map[string]*root.TransparencyLog, error) {
	logs := map[string]*root.TransparencyLog{}
	for _, k := range b64Keys {
		der, derr := base64.StdEncoding.DecodeString(k)
		if derr != nil {
			return nil, fmt.Errorf("decode log key: %w", derr)
		}
		pub, perr := x509.ParsePKIXPublicKey(der)
		if perr != nil {
			return nil, fmt.Errorf("parse log key: %w", perr)
		}
		id := sha256.Sum256(der)
		logs[hex.EncodeToString(id[:])] = &root.TransparencyLog{
			ID:                  id[:],
			ValidityPeriodStart: start,
			ValidityPeriodEnd:   end,
			HashFunc:            crypto.SHA256,
			PublicKey:           pub,
			SignatureHashFunc:   crypto.SHA256,
		}
	}
	return logs, nil
}

func parseDERCerts(b64Certs []string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, c := range b64Certs {
		der, derr := base64.StdEncoding.DecodeString(c)
		if derr != nil {
			return nil, fmt.Errorf("decode fulcio cert: %w", derr)
		}
		cert, cerr := x509.ParseCertificate(der)
		if cerr != nil {
			return nil, fmt.Errorf("parse fulcio cert: %w", cerr)
		}
		out = append(out, cert)
	}
	return out, nil
}

// VerifySignedEntity runs sigstore-go's OFFLINE verifier over a SignedEntity
// (a parsed bundle, or a test entity) against tm, with identity and artifact
// matching intentionally NOT enforced here (WithoutIdentitiesUnsafe records the
// identity for phase 2d; WithoutArtifactUnsafe leaves the subject→bytes binding
// to polypkg's BindSubjects, P6). Any verification error is fail-closed:
// Verified=false, nil error (the caller records verified-transport-only).
func VerifySignedEntity(entity verify.SignedEntity, tm root.TrustedMaterial) (SigstoreVerdict, error) {
	v, err := verify.NewVerifier(tm,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return SigstoreVerdict{}, fmt.Errorf("construct sigstore verifier: %w", err)
	}
	result, verr := v.Verify(entity, verify.NewPolicy(
		verify.WithoutArtifactUnsafe(),
		verify.WithoutIdentitiesUnsafe(),
	))
	if verr != nil {
		return SigstoreVerdict{Verified: false, FailureReason: verr.Error()}, nil // fail closed: unverifiable ⇒ transport-only
	}
	verdict := SigstoreVerdict{Verified: true}
	if result.Signature != nil && result.Signature.Certificate != nil {
		verdict.CertificateIdentity = result.Signature.Certificate.SubjectAlternativeName
		// The OIDC issuer lives in the Fulcio extension (OID 1.3.6.1.4.1.57264.1.8),
		// surfaced as Extensions.Issuer. Summary.CertificateIssuer is the X.509
		// issuer DN (e.g. "CN=sigstore-intermediate,O=sigstore.dev"), not the OIDC
		// issuer — do not use it here.
		verdict.CertificateIssuer = result.Signature.Certificate.Issuer
		verdict.SourceRepositoryURI = result.Signature.Certificate.SourceRepositoryURI
	}
	if result.Statement != nil {
		for _, s := range result.Statement.Subject {
			verdict.Subjects = append(verdict.Subjects, Subject{Name: s.Name, Digest: s.Digest})
		}
	}
	if len(result.VerifiedTimestamps) > 0 {
		verdict.IntegratedTime = result.VerifiedTimestamps[0].Timestamp
	}
	return verdict, nil
}

// VerifySigstoreBundle parses a dev.sigstore.bundle from JSON bytes and verifies
// it offline against tm. A parse failure is a real error (malformed carriage);
// a verification failure is fail-closed inside VerifySignedEntity (Verified=false).
func VerifySigstoreBundle(bundleBytes []byte, tm root.TrustedMaterial) (SigstoreVerdict, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleBytes); err != nil {
		return SigstoreVerdict{}, fmt.Errorf("parse sigstore bundle: %w", err)
	}
	return VerifySignedEntity(&b, tm)
}
