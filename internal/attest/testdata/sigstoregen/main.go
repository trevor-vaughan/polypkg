//go:build ignore

// Command sigstoregen mints the offline-verifiable sigstore fixture the planner
// whitebox tier tests consume: a dev.sigstore.bundle whose inner in-toto subject
// digest is the sha256 of bindable-content.bin, the matching mirrored
// schema.SigstoreRoot, and an unrelated-root.json mirrored from a SECOND,
// independent CA (same validity window, never signed the bundle) for the
// fails-closed-on-wrong-root test. It is a one-time generator, not part of any build (guarded
// by //go:build ignore); run it manually from the repository root, by file path
// so the ignore build tag does not exclude the package:
//
//	go run ./internal/attest/testdata/sigstoregen/main.go
//
// It self-verifies the assembled bundle against the assembled root BEFORE writing
// any file and refuses to emit a fixture that only reaches transport-only. The
// assembly (virtual-CA TestEntity -> hand-marshaled protojson wire bytes, with the
// Rekor SET recomputed because the deprecated tlog.NewEntry omits the inclusion
// promise WithObserverTimestamps requires) mirrors internal/attest's proven
// round-trip test; production bundle.Bundle.UnmarshalJSON parses these bytes.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"

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
	var fulcioDER []string
	for _, cai := range vs.FulcioCertificateAuthorities() {
		fca, ok := cai.(*root.FulcioCertificateAuthority)
		if !ok {
			return schema.SigstoreRoot{}, fmt.Errorf("unexpected certificate authority type %T", cai)
		}
		fulcioDER = append(fulcioDER, base64.StdEncoding.EncodeToString(fca.Root.Raw))
		for _, ic := range fca.Intermediates {
			fulcioDER = append(fulcioDER, base64.StdEncoding.EncodeToString(ic.Raw))
		}
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
// v0.3 JSON. It recomputes the Rekor SET (the virtual CA's deprecated
// tlog.NewEntry omits the inclusion promise WithObserverTimestamps(1) requires)
// via vs.RekorSignPayload; vs must be the VirtualSigstore that produced entity.
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
	rawEnvelope := envelopeContent.RawEnvelope()
	sigs := make([]wireSignature, len(rawEnvelope.Signatures))
	for i, s := range rawEnvelope.Signatures {
		sigs[i] = wireSignature{Sig: s.Sig, KeyID: s.KeyID}
	}
	tlogEntries, err := entity.TlogEntries()
	if err != nil {
		return nil, err
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

	// The generator runs from the repository root (go run ./internal/attest/...),
	// so the sibling testdata dir is a fixed relative path.
	outDir := filepath.Join("internal", "attest", "testdata")
	writes := []struct {
		name string
		data []byte
	}{
		{"bindable-content.bin", content},
		{"bindable-bundle.json", bundleJSON},
		{"bindable-root.json", rootJSON},
		{"unrelated-root.json", unrelatedRootJSON},
	}
	for _, w := range writes {
		path := filepath.Join(outDir, w.name)
		if err := os.WriteFile(path, w.data, 0o644); err != nil { //nolint:gosec // committed test fixtures, world-readable is intended
			return fmt.Errorf("write %s: %w", path, err)
		}
	}

	fmt.Printf("self-verify OK: verified=%t\n", verdict.Verified)
	fmt.Printf("  certificate_identity: %s\n", verdict.CertificateIdentity)
	fmt.Printf("  certificate_issuer:   %s\n", verdict.CertificateIssuer)
	fmt.Printf("cross-verify against unrelated root: verified=%t (expected false)\n", unrelatedVerdict.Verified)
	fmt.Printf("wrote %s/{bindable-content.bin,bindable-bundle.json,bindable-root.json,unrelated-root.json}\n", outDir)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sigstoregen:", err)
		os.Exit(1)
	}
}
