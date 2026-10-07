//go:build ignore

// Command sigstoregen mints offline-verifiable sigstore fixtures. It has two
// fixture sets, chosen with -set.
//
// The bindable set (the default) is what the planner whitebox tier tests
// consume: a dev.sigstore.bundle whose inner in-toto subject digest is the
// sha256 of bindable-content.bin, the matching mirrored schema.SigstoreRoot,
// and an unrelated-root.json mirrored from a SECOND, independent CA (same
// validity window, never signed the bundle) for the fails-closed-on-wrong-root
// test.
//
// The github set is what the GitHub release importer tests consume:
// github-asset.bin (a bare x86-64 ELF executable), github-trusted-root.json (a
// sigstore trusted_root.json, the format TUF distributes) and three bundles
// over the asset whose Fulcio-shaped leaves carry the OIDC issuer and Source
// Repository URI extensions the way Fulcio issues them to GitHub Actions:
// github-bundle.json (acme/tool, GitHub Actions), github-bundle-wrong-repo.json
// (built from mallory/tool) and github-bundle-wrong-issuer.json (a Google
// identity), plus github-bundle-release.json: a GitHub release attestation
// (predicate https://in-toto.io/attestation/release/v0.2, its first subject a
// purl uri as GitHub writes it) from an unrelated CA, standing in for GitHub's
// internal Fulcio, which the root cannot verify.
//
// It is a one-time generator, not part of any build (guarded by
// //go:build ignore); run it manually from the repository root, by file path
// so the ignore build tag does not exclude the package:
//
//	go run ./internal/attest/testdata/sigstoregen/main.go [-set bindable|github]
//
// It self-verifies every assembled bundle against the assembled root BEFORE
// writing any file and refuses to emit a fixture that only reaches
// transport-only. The assembly (hand-marshaled protojson wire bytes, with the
// Rekor SET recomputed because the deprecated tlog.NewEntry omits the
// inclusion promise WithObserverTimestamps requires) mirrors internal/attest's
// proven round-trip test; production bundle.Bundle.UnmarshalJSON parses these
// bytes.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/elf"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

const (
	// san and issuer are the Fulcio identity the fixture bundle certifies; the
	// planner records them (CertificateIdentity/CertificateIssuer) on a
	// verified-offline binding. They are recorded, not gated (phase 2d).
	san    = "https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v1"
	issuer = "https://token.actions.githubusercontent.com"
)

// sigstoreRootFromVirtual mirrors a VirtualSigstore's Fulcio CA chain (root +
// intermediates) and Rekor log keys into polypkg's mirrored SigstoreRoot, over a
// wide 2000-2100 window so any generation-time bundle falls inside it.
func sigstoreRootFromVirtual(vs *ca.VirtualSigstore) (schema.SigstoreRoot, error) {
	var fulcio []*x509.Certificate
	for _, cai := range vs.FulcioCertificateAuthorities() {
		fca, ok := cai.(*root.FulcioCertificateAuthority)
		if !ok {
			return schema.SigstoreRoot{}, fmt.Errorf("unexpected certificate authority type %T", cai)
		}
		fulcio = append(fulcio, fca.Root)
		fulcio = append(fulcio, fca.Intermediates...)
	}
	return mirroredRoot(vs, fulcio...)
}

// mirroredRoot builds a mirrored SigstoreRoot from Fulcio certificates (root
// first, then intermediates) and vs's Rekor log keys, over a wide 2000-2100
// window so any generation-time bundle falls inside it.
func mirroredRoot(vs *ca.VirtualSigstore, fulcio ...*x509.Certificate) (schema.SigstoreRoot, error) {
	fulcioDER := make([]string, 0, len(fulcio))
	for _, c := range fulcio {
		fulcioDER = append(fulcioDER, base64.StdEncoding.EncodeToString(c.Raw))
	}
	rekorDER := make([]string, 0, len(vs.RekorLogs()))
	for _, tl := range vs.RekorLogs() {
		der, err := x509.MarshalPKIXPublicKey(tl.PublicKey)
		if err != nil {
			return schema.SigstoreRoot{}, fmt.Errorf("marshal rekor key: %w", err)
		}
		rekorDER = append(rekorDER, base64.StdEncoding.EncodeToString(der))
	}
	return schema.SigstoreRoot{
		ValidFrom:  "2000-01-01T00:00:00Z",
		ValidUntil: "2100-01-01T00:00:00Z",
		FulcioCA:   fulcioDER,
		RekorKeys:  rekorDER,
	}, nil
}

// The wire* types mirror the protojson shape of dev.sigstore.bundle.v0.3+json so
// this generator can hand-assemble genuine bundle JSON from a TestEntity's own
// exported accessors WITHOUT promoting sigstore's protobuf-specs/rekor packages to
// direct module dependencies (they stay indirect). Production
// bundle.Bundle.UnmarshalJSON parses these bytes for real.
type wireX509Certificate struct {
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
	// protojson encodes proto int64 fields (logIndex, treeSize) as JSON strings;
	// genuine dev.sigstore.bundle documents follow that, so emit strings to keep
	// the fixture faithful to real carriage. bundle.Bundle.UnmarshalJSON (protojson)
	// accepts them, and InspectCarried's standard-json probe requires them.
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
	// logIndex and integratedTime are proto int64 fields: protojson (and thus a
	// genuine bundle) encodes them as JSON strings — see wireInclusionProof.
	LogIndex          string                `json:"logIndex"`
	LogID             wireLogID             `json:"logId"`
	KindVersion       wireKindVersion       `json:"kindVersion"`
	IntegratedTime    string                `json:"integratedTime"`
	InclusionPromise  *wireInclusionPromise `json:"inclusionPromise,omitempty"`
	InclusionProof    *wireInclusionProof   `json:"inclusionProof,omitempty"`
	CanonicalizedBody string                `json:"canonicalizedBody"`
}
type wireVerificationMaterial struct {
	Certificate wireX509Certificate `json:"certificate"`
	TlogEntries []wireTlogEntry     `json:"tlogEntries"`
}
type wireSignature struct {
	Sig   string `json:"sig"`
	KeyID string `json:"keyid,omitempty"`
}
type wireDSSEEnvelope struct {
	Payload     string          `json:"payload"`
	PayloadType string          `json:"payloadType"`
	Signatures  []wireSignature `json:"signatures"`
}
type wireBundle struct {
	MediaType            string                   `json:"mediaType"`
	VerificationMaterial wireVerificationMaterial `json:"verificationMaterial"`
	DsseEnvelope         wireDSSEEnvelope         `json:"dsseEnvelope"`
}

// bundleJSONFromEntity serializes a TestEntity into genuine dev.sigstore.bundle
// v0.3 JSON; vs must be the VirtualSigstore that produced entity.
func bundleJSONFromEntity(vs *ca.VirtualSigstore, entity *ca.TestEntity) ([]byte, error) {
	vc, err := entity.VerificationContent()
	if err != nil {
		return nil, err
	}
	cert := vc.Certificate()
	if cert == nil {
		return nil, fmt.Errorf("verification content has no certificate")
	}
	sc, err := entity.SignatureContent()
	if err != nil {
		return nil, err
	}
	envelopeContent := sc.EnvelopeContent()
	if envelopeContent == nil {
		return nil, fmt.Errorf("signature content has no DSSE envelope")
	}
	tlogEntries, err := entity.TlogEntries()
	if err != nil {
		return nil, err
	}
	return wireBundleJSON(vs, cert, envelopeContent.RawEnvelope(), tlogEntries)
}

// wireBundleJSON serializes a leaf certificate, its DSSE envelope and their
// Rekor entries into genuine dev.sigstore.bundle v0.3 JSON. It recomputes the
// Rekor SET (the virtual CA's deprecated tlog.NewEntry omits the inclusion
// promise WithObserverTimestamps(1) requires) via vs.RekorSignPayload; vs must
// be the VirtualSigstore whose Rekor log produced the entries.
func wireBundleJSON(vs *ca.VirtualSigstore, cert *x509.Certificate, rawEnvelope *dsse.Envelope, tlogEntries []*tlog.Entry) ([]byte, error) {
	sigs := make([]wireSignature, len(rawEnvelope.Signatures))
	for i, s := range rawEnvelope.Signatures {
		sigs[i] = wireSignature{Sig: s.Sig, KeyID: s.KeyID}
	}
	wireEntries := make([]wireTlogEntry, len(tlogEntries))
	for i, e := range tlogEntries {
		tle := e.TransparencyLogEntry()
		// Every entry vs.Attest produces is a Rekor "dsse" v0.0.1 entry, but the
		// deprecated tlog.NewEntry never writes KindVersion onto the proto; default
		// to what the real Rekor pipeline would have recorded.
		kind, version := "dsse", "0.0.1"
		if kv := tle.GetKindVersion(); kv != nil {
			kind, version = kv.GetKind(), kv.GetVersion()
		}
		set, serr := vs.RekorSignPayload(tlog.RekorPayload{
			Body:           e.Body(),
			IntegratedTime: e.IntegratedTime().Unix(),
			LogIndex:       e.LogIndex(),
			LogID:          hex.EncodeToString([]byte(e.LogKeyID())),
		})
		if serr != nil {
			return nil, serr
		}
		var proof *wireInclusionProof
		if ip := tle.GetInclusionProof(); ip != nil {
			hashes := make([]string, len(ip.GetHashes()))
			for j, h := range ip.GetHashes() {
				hashes[j] = base64.StdEncoding.EncodeToString(h)
			}
			proof = &wireInclusionProof{
				LogIndex:   strconv.FormatInt(ip.GetLogIndex(), 10),
				RootHash:   base64.StdEncoding.EncodeToString(ip.GetRootHash()),
				TreeSize:   strconv.FormatInt(ip.GetTreeSize(), 10),
				Hashes:     hashes,
				Checkpoint: wireCheckpoint{Envelope: ip.GetCheckpoint().GetEnvelope()},
			}
		}
		wireEntries[i] = wireTlogEntry{
			LogIndex:          strconv.FormatInt(e.LogIndex(), 10),
			LogID:             wireLogID{KeyID: base64.StdEncoding.EncodeToString([]byte(e.LogKeyID()))},
			KindVersion:       wireKindVersion{Kind: kind, Version: version},
			IntegratedTime:    strconv.FormatInt(e.IntegratedTime().Unix(), 10),
			InclusionPromise:  &wireInclusionPromise{SignedEntryTimestamp: base64.StdEncoding.EncodeToString(set)},
			InclusionProof:    proof,
			CanonicalizedBody: base64.StdEncoding.EncodeToString(tle.GetCanonicalizedBody()),
		}
	}
	wb := wireBundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: wireVerificationMaterial{
			Certificate: wireX509Certificate{RawBytes: base64.StdEncoding.EncodeToString(cert.Raw)},
			TlogEntries: wireEntries,
		},
		DsseEnvelope: wireDSSEEnvelope{
			Payload:     rawEnvelope.Payload,
			PayloadType: rawEnvelope.PayloadType,
			Signatures:  sigs,
		},
	}
	return json.Marshal(wb)
}

// inTotoStatement builds the in-toto v1 Statement the bundle attests: one subject
// over the sha256 of content, SLSA provenance predicateType, empty predicate. The
// subject name is advisory (BindSubjects binds by digest, not name).
func inTotoStatement(content []byte) ([]byte, error) {
	sum := sha256.Sum256(content)
	st := map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []map[string]any{{
			"name":   "bin/app",
			"digest": map[string]string{"sha256": hex.EncodeToString(sum[:])},
		}},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate":     map[string]any{},
	}
	return json.Marshal(st)
}

func run() error {
	content := []byte("polypkg sigstore fixture")

	statementJSON, err := inTotoStatement(content)
	if err != nil {
		return fmt.Errorf("build in-toto statement: %w", err)
	}

	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		return fmt.Errorf("new virtual sigstore: %w", err)
	}
	entity, err := vs.AttestAtTime(san, issuer, statementJSON, time.Now(), true)
	if err != nil {
		return fmt.Errorf("attest: %w", err)
	}
	bundleJSON, err := bundleJSONFromEntity(vs, entity)
	if err != nil {
		return fmt.Errorf("assemble bundle: %w", err)
	}
	sroot, err := sigstoreRootFromVirtual(vs)
	if err != nil {
		return fmt.Errorf("assemble sigstore root: %w", err)
	}
	rootJSON, err := json.MarshalIndent(sroot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sigstore root: %w", err)
	}

	// Self-verify gate: never write a fixture that only reaches transport-only.
	tm, err := attest.SigstoreTrustedMaterial(sroot)
	if err != nil {
		return fmt.Errorf("build trusted material for self-verify: %w", err)
	}
	verdict, err := attest.VerifySigstoreBundle(bundleJSON, tm)
	if err != nil {
		return fmt.Errorf("self-verify bundle: %w", err)
	}
	if !verdict.Verified {
		return fmt.Errorf("self-verify FAILED: assembled bundle does not verify offline (would only reach transport-only); refusing to write fixtures")
	}

	// A SECOND, independent virtual CA: its mirrored root shares the wide
	// 2000-2100 window (so SigstoreRootAt selects it for the bindable bundle's
	// integrated time and the kernel is genuinely reached) but never signed the
	// bundle. The wrong-root negative test proves the kernel rejects it and no
	// identity leaks — exercising the innermost verdict.Verified gate that a nil
	// bundle short-circuits past.
	unrelatedVS, err := ca.NewVirtualSigstore()
	if err != nil {
		return fmt.Errorf("new unrelated virtual sigstore: %w", err)
	}
	unrelatedRoot, err := sigstoreRootFromVirtual(unrelatedVS)
	if err != nil {
		return fmt.Errorf("assemble unrelated sigstore root: %w", err)
	}
	unrelatedRootJSON, err := json.MarshalIndent(unrelatedRoot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal unrelated sigstore root: %w", err)
	}
	// Confirm the unrelated root really does NOT verify the bundle: if it somehow
	// did, the negative fixture would be a false negative. Fail closed.
	unrelatedTM, err := attest.SigstoreTrustedMaterial(unrelatedRoot)
	if err != nil {
		return fmt.Errorf("build trusted material for unrelated root: %w", err)
	}
	unrelatedVerdict, err := attest.VerifySigstoreBundle(bundleJSON, unrelatedTM)
	if err != nil {
		return fmt.Errorf("cross-verify against unrelated root: %w", err)
	}
	if unrelatedVerdict.Verified {
		return fmt.Errorf("unrelated root unexpectedly VERIFIED the bundle; the negative fixture would be a false negative")
	}

	fmt.Printf("self-verify OK: verified=%t\n", verdict.Verified)
	fmt.Printf("  certificate_identity: %s\n", verdict.CertificateIdentity)
	fmt.Printf("  certificate_issuer:   %s\n", verdict.CertificateIssuer)
	fmt.Printf("cross-verify against unrelated root: verified=%t (expected false)\n", unrelatedVerdict.Verified)
	return writeFixtures([]fixtureFile{
		{"bindable-content.bin", content},
		{"bindable-bundle.json", bundleJSON},
		{"bindable-root.json", rootJSON},
		{"unrelated-root.json", unrelatedRootJSON},
	})
}

// fixtureFile is one file the generator writes into internal/attest/testdata.
type fixtureFile struct {
	name string
	data []byte
}

// writeFixtures writes files into internal/attest/testdata. The generator runs
// from the repository root, so that is a fixed relative path.
func writeFixtures(files []fixtureFile) error {
	outDir := filepath.Join("internal", "attest", "testdata")
	for _, f := range files {
		path := filepath.Join(outDir, f.name)
		if err := os.WriteFile(path, f.data, 0o644); err != nil { //nolint:gosec // committed test fixtures, world-readable is intended
			return fmt.Errorf("write %s: %w", path, err)
		}
		fmt.Printf("wrote %s\n", path)
	}
	return nil
}

// The github set's identities. githubRepo is the repository the genuine
// bundle attests; githubForeignRepo is the one the wrong-repository bundle
// names; googleIssuer is a Fulcio OIDC issuer that is not GitHub Actions.
const (
	githubRepo        = "https://github.com/acme/tool"
	githubForeignRepo = "https://github.com/mallory/tool"
	googleIssuer      = "https://accounts.google.com"
	// releasePredicateType is the in-toto predicate of GitHub's release
	// attestations, which attest an asset's membership in a release rather
	// than how it was built.
	releasePredicateType = "https://in-toto.io/attestation/release/v0.2"
)

var (
	// The Fulcio extensions the github set's leaves carry, each a DER
	// UTF8String as Fulcio writes them.
	oidIssuerV2            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
	oidSourceRepositoryURI = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}

	// githubAsset is the attested release asset: an x86-64 ELF header, so the
	// importer classifies it as a bare linux/amd64 executable, then fixed text.
	githubAsset = append(amd64ELFHeader(), "polypkg github import attestation fixture\n"...)
)

// amd64ELFHeader returns the 64-byte header of a little-endian x86-64 ELF
// executable with no program or section headers: the least debug/elf parses
// and reports a machine for.
func amd64ELFHeader() []byte {
	h := make([]byte, 64)
	copy(h, []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	binary.LittleEndian.PutUint16(h[16:], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(h[18:], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(h[20:], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint16(h[52:], 64) // e_ehsize
	return h
}

// githubLeaf issues a leaf certificate shaped like the one Fulcio issues to a
// GitHub Actions workflow: a URI SAN naming the workflow, and the OIDC issuer
// and Source Repository URI extensions. parent and parentKey are the Fulcio
// intermediate that signs it.
func githubLeaf(parent *x509.Certificate, parentKey crypto.Signer, oidcIssuer, sourceRepo string, notBefore time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	issuerDER, err := asn1.MarshalWithParams(oidcIssuer, "utf8")
	if err != nil {
		return nil, nil, err
	}
	repoDER, err := asn1.MarshalWithParams(sourceRepo, "utf8")
	if err != nil {
		return nil, nil, err
	}
	san, err := url.Parse(sourceRepo + "/.github/workflows/release.yml@refs/tags/v1.2.3")
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		URIs:         []*url.URL{san},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(10 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{
			{Id: oidIssuerV2, Value: issuerDER},
			{Id: oidSourceRepositoryURI, Value: repoDER},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// githubBundle signs statement as a DSSE in-toto envelope with a fresh
// githubLeaf, enters it in vs's Rekor log, and returns the bundle JSON.
func githubBundle(vs *ca.VirtualSigstore, parent *x509.Certificate, parentKey crypto.Signer, oidcIssuer, sourceRepo string, statement []byte) ([]byte, error) {
	now := time.Now()
	leaf, key, err := githubLeaf(parent, parentKey, oidcIssuer, sourceRepo, now.Add(-time.Minute))
	if err != nil {
		return nil, fmt.Errorf("issue leaf certificate: %w", err)
	}
	signer, err := signature.LoadECDSASigner(key, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	es, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{SignatureSigner: signer, Pub: &key.PublicKey})
	if err != nil {
		return nil, err
	}
	env, err := es.SignPayload(context.Background(), "application/vnd.in-toto+json", statement)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return nil, err
	}
	entry, err := vs.GenerateTlogEntry(leaf, env, sig, now.Unix(), true)
	if err != nil {
		return nil, fmt.Errorf("enter the bundle in rekor: %w", err)
	}
	return wireBundleJSON(vs, leaf, env, []*tlog.Entry{entry})
}

// runGitHub mints the github fixture set.
func runGitHub() error {
	ef, err := elf.NewFile(bytes.NewReader(githubAsset))
	if err != nil || ef.Machine != elf.EM_X86_64 {
		return fmt.Errorf("self-check github-asset.bin FAILED: not an x86-64 ELF (err %v)", err)
	}
	sum := sha256.Sum256(githubAsset)
	statementFor := func(predicateType string) ([]byte, error) {
		return json.Marshal(map[string]any{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": []map[string]any{{
				"name":   "tool-linux-amd64",
				"digest": map[string]string{"sha256": hex.EncodeToString(sum[:])},
			}},
			"predicateType": predicateType,
			"predicate":     map[string]any{},
		})
	}
	statement, err := statementFor("https://slsa.dev/provenance/v1")
	if err != nil {
		return fmt.Errorf("build in-toto statement: %w", err)
	}

	// vs supplies the Rekor log every bundle is entered in. Its own Fulcio CA
	// keeps its intermediate key private, so the leaves come from a separate
	// root and intermediate, which the trusted root lists instead.
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		return fmt.Errorf("new virtual sigstore: %w", err)
	}
	fulcioRoot, fulcioRootKey, err := ca.GenerateRootCa()
	if err != nil {
		return fmt.Errorf("generate fulcio root: %w", err)
	}
	fulcioInter, fulcioInterKey, err := ca.GenerateFulcioIntermediate(fulcioRoot, fulcioRootKey)
	if err != nil {
		return fmt.Errorf("generate fulcio intermediate: %w", err)
	}
	sroot, err := mirroredRoot(vs, fulcioRoot, fulcioInter)
	if err != nil {
		return err
	}
	tm, err := attest.SigstoreTrustedMaterial(sroot)
	if err != nil {
		return fmt.Errorf("build trusted material: %w", err)
	}
	tr, ok := tm.(*root.TrustedRoot)
	if !ok {
		return fmt.Errorf("unexpected trusted material type %T", tm)
	}
	compact, err := tr.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal trusted root: %w", err)
	}
	var rootJSON bytes.Buffer
	if err := json.Indent(&rootJSON, compact, "", "  "); err != nil {
		return fmt.Errorf("indent trusted root: %w", err)
	}
	// Self-verify against the root parsed back from the very bytes written,
	// as the importer reads them.
	parsed, err := root.NewTrustedRootFromJSON(rootJSON.Bytes())
	if err != nil {
		return fmt.Errorf("parse trusted root: %w", err)
	}

	files := []fixtureFile{
		{"github-asset.bin", githubAsset},
		{"github-trusted-root.json", rootJSON.Bytes()},
	}
	for _, b := range []struct{ name, issuer, repo string }{
		{"github-bundle.json", issuer, githubRepo},
		{"github-bundle-wrong-repo.json", issuer, githubForeignRepo},
		{"github-bundle-wrong-issuer.json", googleIssuer, githubRepo},
	} {
		bundleJSON, err := githubBundle(vs, fulcioInter, fulcioInterKey, b.issuer, b.repo, statement)
		if err != nil {
			return fmt.Errorf("assemble %s: %w", b.name, err)
		}
		verdict, err := attest.VerifySigstoreBundle(bundleJSON, parsed)
		if err != nil {
			return fmt.Errorf("self-verify %s: %w", b.name, err)
		}
		if !verdict.Verified || verdict.CertificateIssuer != b.issuer || verdict.SourceRepositoryURI != b.repo {
			return fmt.Errorf("self-verify %s FAILED: verified=%t issuer=%q source repository=%q; refusing to write fixtures",
				b.name, verdict.Verified, verdict.CertificateIssuer, verdict.SourceRepositoryURI)
		}
		fmt.Printf("self-verify %s OK: issuer=%s source repository=%s\n", b.name, verdict.CertificateIssuer, verdict.SourceRepositoryURI)
		files = append(files, fixtureFile{b.name, bundleJSON})
	}

	// GitHub also attests every release asset with a release attestation,
	// signed by GitHub's own Fulcio instance, which the public-good root can
	// never verify. Its subjects are shaped as GitHub writes them: the
	// release itself as an in-toto ResourceDescriptor with a purl uri and the
	// tagged commit's sha1, then each asset by name and sha256. Mint one from
	// an unrelated virtual CA and prove both halves: its predicate type reads
	// without verification, and it does not verify against the github set's
	// root.
	releaseStatement, err := json.Marshal(map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []map[string]any{
			{
				"uri":    "pkg:github/acme/tool@v1.2.3",
				"digest": map[string]string{"sha1": "fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd"},
			},
			{
				"name":   "tool-linux-amd64",
				"digest": map[string]string{"sha256": hex.EncodeToString(sum[:])},
			},
		},
		"predicateType": releasePredicateType,
		"predicate":     map[string]any{},
	})
	if err != nil {
		return fmt.Errorf("build release statement: %w", err)
	}
	githubInternal, err := ca.NewVirtualSigstore()
	if err != nil {
		return fmt.Errorf("new unrelated virtual sigstore: %w", err)
	}
	entity, err := githubInternal.AttestAtTime(githubRepo+"/.github/workflows/release.yml@refs/tags/v1.2.3", issuer, releaseStatement, time.Now(), true)
	if err != nil {
		return fmt.Errorf("attest release: %w", err)
	}
	releaseJSON, err := bundleJSONFromEntity(githubInternal, entity)
	if err != nil {
		return fmt.Errorf("assemble github-bundle-release.json: %w", err)
	}
	var releaseBundle struct {
		DSSEEnvelope struct {
			Payload []byte `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	var releaseHead struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(releaseJSON, &releaseBundle); err != nil {
		return fmt.Errorf("self-check github-bundle-release.json: %w", err)
	}
	if err := json.Unmarshal(releaseBundle.DSSEEnvelope.Payload, &releaseHead); err != nil || releaseHead.PredicateType != releasePredicateType {
		return fmt.Errorf("self-check github-bundle-release.json FAILED: predicate type %q (err %v)", releaseHead.PredicateType, err)
	}
	releaseVerdict, err := attest.VerifySigstoreBundle(releaseJSON, parsed)
	if err != nil {
		return fmt.Errorf("cross-verify github-bundle-release.json: %w", err)
	}
	if releaseVerdict.Verified {
		return fmt.Errorf("github-bundle-release.json unexpectedly VERIFIED against the github root; the fixture would not model a GitHub-internal signature")
	}
	fmt.Printf("self-check github-bundle-release.json OK: predicate type %s, verified=false (expected)\n", releaseHead.PredicateType)
	files = append(files, fixtureFile{"github-bundle-release.json", releaseJSON})
	return writeFixtures(files)
}

func main() {
	set := flag.String("set", "bindable", "fixture set to mint: bindable or github")
	flag.Parse()
	var err error
	switch *set {
	case "bindable":
		err = run()
	case "github":
		err = runGitHub()
	default:
		err = fmt.Errorf("unknown -set %q (want bindable or github)", *set)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sigstoregen:", err)
		os.Exit(1)
	}
}
