package repo

import (
	"strings"
	"testing"

	"github.com/jedisct1/go-minisign"
)

func TestKeypairSignVerifiesWithGoMinisign(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	data := []byte("hello repo")
	sig := kp.SignWithComment(data, "polypkg repo signature", "name=hello version=1.0.0")

	pub, err := minisign.DecodePublicKey(kp.PublicKeyFile("test key"))
	if err != nil {
		t.Fatalf("DecodePublicKey: %v", err)
	}
	s, err := minisign.DecodeSignature(sig)
	if err != nil {
		t.Fatalf("DecodeSignature: %v", err)
	}
	ok, err := pub.Verify(data, s)
	if err != nil || !ok {
		t.Fatalf("Verify ok=%v err=%v", ok, err)
	}
}

func TestSignArtifactCommentBindsNameVersionHash(t *testing.T) {
	kp, _ := GenerateKeypair()
	art := []byte("artifact-bytes")
	sig := kp.SignArtifact("hello", "1.0.0", art)
	want := "name=hello version=1.0.0 hash=" + ContentHash(art)
	s, err := minisign.DecodeSignature(sig)
	if err != nil {
		t.Fatalf("DecodeSignature: %v", err)
	}
	// go-minisign stores TrustedComment with the "trusted comment: " prefix verbatim.
	tc := s.TrustedComment
	bare := strings.TrimPrefix(tc, "trusted comment: ")
	if bare != want {
		t.Fatalf("trusted comment = %q want %q", tc, "trusted comment: "+want)
	}
}

func TestSignAttestationComment(t *testing.T) {
	kp, _ := GenerateKeypair()
	data := []byte(`{"x":1}`)
	sig := kp.SignAttestation("hello", "1.0.0", data)
	if !strings.Contains(sig, "trusted comment: name=hello version=1.0.0 hash="+ContentHash(data)) {
		t.Fatalf("attestation trusted comment wrong:\n%s", sig)
	}
	if !strings.Contains(sig, "untrusted comment: polypkg attestation signature") {
		t.Fatalf("attestation untrusted comment wrong:\n%s", sig)
	}
}

func TestKeypairFromSeedRoundTrip(t *testing.T) {
	kp, _ := GenerateKeypair()
	kp2, err := KeypairFromSeed(kp.Seed(), kp.KeyID())
	if err != nil {
		t.Fatalf("KeypairFromSeed: %v", err)
	}
	if kp2.PublicKeyBase64() != kp.PublicKeyBase64() {
		t.Fatal("seed round-trip changed public key")
	}
}
