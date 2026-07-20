package attest_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func inTotoBody(predicateType string) []byte {
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"name": "bin/hello", "digest": map[string]string{"sha256": "abc123"}}},
		"predicateType": predicateType,
		"predicate":     map[string]any{},
	}
	b, _ := json.Marshal(st)
	return b
}

func sigstoreRootFromVirtual(vs *ca.VirtualSigstore) schema.SigstoreRoot {
	var fulcioDER []string
	for _, cai := range vs.FulcioCertificateAuthorities() {
		fca := cai.(*root.FulcioCertificateAuthority)
		fulcioDER = append(fulcioDER, base64.StdEncoding.EncodeToString(fca.Root.Raw))
		for _, ic := range fca.Intermediates {
			fulcioDER = append(fulcioDER, base64.StdEncoding.EncodeToString(ic.Raw))
		}
	}
	rekorDER := make([]string, 0, len(vs.RekorLogs()))
	for _, tl := range vs.RekorLogs() {
		der, err := x509.MarshalPKIXPublicKey(tl.PublicKey)
		Expect(err).NotTo(HaveOccurred())
		rekorDER = append(rekorDER, base64.StdEncoding.EncodeToString(der))
	}
	return schema.SigstoreRoot{
		ValidFrom:  "2000-01-01T00:00:00Z",
		ValidUntil: "2100-01-01T00:00:00Z",
		FulcioCA:   fulcioDER,
		RekorKeys:  rekorDER,
	}
}

var _ = Describe("sigstore bundle verification kernel", func() {
	const (
		san    = "https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v1"
		issuer = "https://token.actions.githubusercontent.com"
	)

	It("verifies a genuine bundle against adapter-built trust material and records identity + subjects", func() {
		vs, err := ca.NewVirtualSigstore()
		Expect(err).NotTo(HaveOccurred())
		entity, err := vs.AttestAtTime(san, issuer, inTotoBody("https://slsa.dev/provenance/v1"), time.Now(), true)
		Expect(err).NotTo(HaveOccurred())

		tm, err := attest.SigstoreTrustedMaterial(sigstoreRootFromVirtual(vs))
		Expect(err).NotTo(HaveOccurred())

		verdict, err := attest.VerifySignedEntity(entity, tm)
		Expect(err).NotTo(HaveOccurred())
		Expect(verdict.Verified).To(BeTrue())
		Expect(verdict.CertificateIdentity).To(Equal(san))
		Expect(verdict.CertificateIssuer).To(Equal(issuer))
		Expect(verdict.Subjects).To(HaveLen(1))
		Expect(verdict.Subjects[0].Digest).To(HaveKeyWithValue("sha256", "abc123"))
	})

	It("does not verify a bundle against an unrelated trust root", func() {
		vs, err := ca.NewVirtualSigstore()
		Expect(err).NotTo(HaveOccurred())
		entity, err := vs.Attest(san, issuer, inTotoBody("https://slsa.dev/provenance/v1"))
		Expect(err).NotTo(HaveOccurred())

		other, err := ca.NewVirtualSigstore()
		Expect(err).NotTo(HaveOccurred())
		tm, err := attest.SigstoreTrustedMaterial(sigstoreRootFromVirtual(other))
		Expect(err).NotTo(HaveOccurred())

		verdict, err := attest.VerifySignedEntity(entity, tm)
		Expect(err).NotTo(HaveOccurred())
		Expect(verdict.Verified).To(BeFalse())
	})

	It("errors when the SigstoreRoot has no Fulcio CA", func() {
		_, err := attest.SigstoreTrustedMaterial(schema.SigstoreRoot{ValidFrom: "2000-01-01T00:00:00Z", ValidUntil: "2100-01-01T00:00:00Z"})
		Expect(err).To(HaveOccurred())
	})

	It("selects the self-signed Fulcio cert as the trust anchor regardless of chain order", func() {
		vs, err := ca.NewVirtualSigstore()
		Expect(err).NotTo(HaveOccurred())
		sr := sigstoreRootFromVirtual(vs) // root-first order
		// reversed copy (root-last)
		rev := make([]string, len(sr.FulcioCA))
		for i, c := range sr.FulcioCA {
			rev[len(sr.FulcioCA)-1-i] = c
		}
		for _, order := range [][]string{sr.FulcioCA, rev} {
			r := sr
			r.FulcioCA = order
			tm, err := attest.SigstoreTrustedMaterial(r)
			Expect(err).NotTo(HaveOccurred())
			cas := tm.FulcioCertificateAuthorities()
			Expect(cas).To(HaveLen(1))
			fca := cas[0].(*root.FulcioCertificateAuthority)
			// the chosen Root must be self-signed (RawSubject == RawIssuer)
			Expect(fca.Root.RawSubject).To(Equal(fca.Root.RawIssuer))
		}
	})

	It("errors on malformed bundle bytes", func() {
		vs, err := ca.NewVirtualSigstore()
		Expect(err).NotTo(HaveOccurred())
		tm, err := attest.SigstoreTrustedMaterial(sigstoreRootFromVirtual(vs))
		Expect(err).NotTo(HaveOccurred())
		_, err = attest.VerifySigstoreBundle([]byte(`{"not":"a bundle"}`), tm)
		Expect(err).To(HaveOccurred())
	})
})
