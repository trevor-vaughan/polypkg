package repo

import (
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/trust"
)

func TestSignTrustBundleVerifiesUnderPublicKey(t *testing.T) {
	k, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	doc := []byte(`{"schema":"polypkg.trust-bundle/v1","source":"native","serial":3,"expires":"2099-01-01T00:00:00Z"}`)
	sig := k.SignTrustBundle(3, doc)
	if err := trust.Verify(k.PublicKeyFile("bundle test"), doc, sig); err != nil {
		t.Fatalf("SignTrustBundle output failed to verify: %v", err)
	}
	// Tampered document must not verify.
	if err := trust.Verify(k.PublicKeyFile("bundle test"), []byte("tampered"), sig); err == nil {
		t.Fatal("expected verification failure on tampered document, got nil")
	}
}

func TestSignRevocationListVerifiesUnderPublicKey(t *testing.T) {
	k, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	doc := []byte(`{"schema":"polypkg.revocation-list/v1","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z"}`)
	sig := k.SignRevocationList(1, doc)
	if err := trust.Verify(k.PublicKeyFile("revocation test"), doc, sig); err != nil {
		t.Fatalf("SignRevocationList output failed to verify: %v", err)
	}
}
