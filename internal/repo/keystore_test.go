package repo

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyStoreRoundTrip(t *testing.T) {
	for _, kdf := range []KDF{KDFScrypt, KDFPBKDF2} {
		t.Run(string(kdf), func(t *testing.T) {
			kp, err := GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "k.key")
			if err := SaveKey(path, kp, "correct horse", kdf); err != nil {
				t.Fatalf("SaveKey: %v", err)
			}
			fi, err := os.Stat(path)
			if err != nil || fi.Mode().Perm() != 0o600 {
				t.Fatalf("key file mode = %v (err %v)", fi.Mode().Perm(), err)
			}
			got, err := LoadKey(path, "correct horse")
			if err != nil {
				t.Fatalf("LoadKey: %v", err)
			}
			if got.PublicKeyBase64() != kp.PublicKeyBase64() {
				t.Fatal("round-trip changed public key")
			}
		})
	}
}

func TestKeyStoreWrongPassword(t *testing.T) {
	kp, _ := GenerateKeypair()
	path := filepath.Join(t.TempDir(), "k.key")
	if err := SaveKey(path, kp, "right", KDFScrypt); err != nil {
		t.Fatal(err)
	}
	_, err := LoadKey(path, "wrong")
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}
}

func TestKeyStoreTamperedCiphertextRejected(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "k.key")
	if err := SaveKey(path, kp, "correct horse", KDFScrypt); err != nil {
		t.Fatal(err)
	}

	// Read and unmarshal the on-disk container using a local struct that
	// mirrors the json tags of the unexported encryptedKey type.
	type keyFile struct {
		Schema     string `json:"schema"`
		KDF        string `json:"kdf"`
		Salt       string `json:"salt"`
		N          int    `json:"n,omitempty"`
		R          int    `json:"r,omitempty"`
		P          int    `json:"p,omitempty"`
		Iter       int    `json:"iter,omitempty"`
		KeyID      string `json:"key_id"`
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		t.Fatal(err)
	}

	ct, err := base64.StdEncoding.DecodeString(kf.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0xff
	kf.Ciphertext = base64.StdEncoding.EncodeToString(ct)

	tampered, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = LoadKey(path, "correct horse")
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("expected ErrWrongPassword for tampered ciphertext, got %v", err)
	}
}

// keyFileFields mirrors the json tags of the unexported encryptedKey type so a
// test can rewrite individual on-disk parameters.
type keyFileFields struct {
	Schema     string `json:"schema"`
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`
	N          int    `json:"n,omitempty"`
	R          int    `json:"r,omitempty"`
	P          int    `json:"p,omitempty"`
	Iter       int    `json:"iter,omitempty"`
	KeyID      string `json:"key_id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// TestKeyStoreOversizedScryptParamsRejected ensures a crafted or corrupt key
// file cannot drive scrypt into a huge memory allocation. scrypt's working
// memory scales with both r (the 128*N*r block array) and p (the p*128*r
// buffer); bounding only N is insufficient, so r and p must be capped too. The
// load must reject before deriveKey runs — i.e. with a parameter error, not a
// post-decryption ErrWrongPassword and not an out-of-memory crash.
func TestKeyStoreOversizedScryptParamsRejected(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*keyFileFields)
	}{
		{"oversized r", func(kf *keyFileFields) { kf.R = scryptRCap + 1 }},
		{"oversized p", func(kf *keyFileFields) { kf.P = scryptPCap + 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kp, err := GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "k.key")
			if err := SaveKey(path, kp, "correct horse", KDFScrypt); err != nil {
				t.Fatal(err)
			}

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var kf keyFileFields
			if err := json.Unmarshal(raw, &kf); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&kf)
			out, err := json.MarshalIndent(kf, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, out, 0o600); err != nil {
				t.Fatal(err)
			}

			_, err = LoadKey(path, "correct horse")
			if err == nil {
				t.Fatal("expected an error for oversized scrypt parameters, got nil")
			}
			if errors.Is(err, ErrWrongPassword) {
				t.Fatalf("params should be rejected before decryption, got ErrWrongPassword: %v", err)
			}
		})
	}
}

// TestKeyStoreOversizedPBKDF2IterRejected ensures an oversized PBKDF2 iteration
// count is rejected before deriveKey runs, bounding the HMAC loop a crafted or
// corrupt file could otherwise drive.
func TestKeyStoreOversizedPBKDF2IterRejected(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "k.key")
	if err := SaveKey(path, kp, "correct horse", KDFPBKDF2); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var kf keyFileFields
	if err := json.Unmarshal(raw, &kf); err != nil {
		t.Fatal(err)
	}
	kf.Iter = pbkdf2IterCap + 1
	out, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = LoadKey(path, "correct horse")
	if err == nil {
		t.Fatal("expected an error for oversized pbkdf2 iter, got nil")
	}
	if errors.Is(err, ErrWrongPassword) {
		t.Fatalf("iter should be rejected before decryption, got ErrWrongPassword: %v", err)
	}
}

func TestKeyStoreUnknownSchemaRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.key")
	raw := []byte(`{"schema":"polypkg.repo-key/v2","kdf":"scrypt","salt":"","key_id":"","nonce":"","ciphertext":""}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadKey(path, "any")
	if err == nil {
		t.Fatal("expected error for unknown schema, got nil")
	}
}
