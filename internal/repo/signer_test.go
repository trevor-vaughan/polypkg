package repo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jedisct1/go-minisign"

	"github.com/trevor-vaughan/polypkg/internal/platform"
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

func TestSignArtifactCommentBindsNameVersionPlatformHash(t *testing.T) {
	kp, _ := GenerateKeypair()
	art := []byte("artifact-bytes")
	for _, tc := range []struct {
		platform string
		want     string
	}{
		{platform: "", want: platform.Any}, // platform-agnostic signs the reserved token
		{platform: "linux/amd64", want: "linux/amd64"},
	} {
		sig := kp.SignArtifact("hello", "1.0.0", tc.platform, art)
		want := "name=hello version=1.0.0 platform=" + tc.want + " hash=" + ContentHash(art)
		s, err := minisign.DecodeSignature(sig)
		if err != nil {
			t.Fatalf("platform %q: DecodeSignature: %v", tc.platform, err)
		}
		// go-minisign stores TrustedComment with the "trusted comment: " prefix verbatim.
		bare := strings.TrimPrefix(s.TrustedComment, "trusted comment: ")
		if bare != want {
			t.Fatalf("platform %q: trusted comment = %q want %q", tc.platform, bare, want)
		}
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
	if strings.Contains(sig, "platform=") {
		t.Fatalf("attestation trusted comment must not carry a platform (it binds by digest):\n%s", sig)
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

// TestBuildSignsArtifactWithEntryPlatform checks the emitPackage wiring: the
// published artifact signature binds the same platform the index entry
// publishes (the test package declares none, so the entry is
// platform-agnostic and the claim is the reserved "any").
func TestBuildSignsArtifactWithEntryPlatform(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	pub := filepath.Join(filepath.Dir(mPath), "public")
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	e := readIndex(t, pub).Packages["hello"][0]
	if e.Platform != "" {
		t.Fatalf("entry platform = %q, want \"\" (the test package declares no platform)", e.Platform)
	}
	raw, err := os.ReadFile(filepath.Join(pub, e.Artifact+".minisig"))
	if err != nil {
		t.Fatalf("read artifact signature: %v", err)
	}
	s, err := minisign.DecodeSignature(string(raw))
	if err != nil {
		t.Fatalf("DecodeSignature: %v", err)
	}
	want := "name=hello version=" + e.Version + " platform=" + platform.Any + " hash=" + e.ContentHash
	if bare := strings.TrimPrefix(s.TrustedComment, "trusted comment: "); bare != want {
		t.Fatalf("artifact trusted comment = %q want %q", bare, want)
	}
}
