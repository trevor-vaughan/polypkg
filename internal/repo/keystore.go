package repo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/scrypt"
)

// KDF selects the password-based key-derivation function wrapping the secret
// key. scrypt is the default; pbkdf2 is FIPS-approved (used in FIPS builds).
type KDF string

// KDFScrypt uses scrypt for key derivation (the default).
// KDFPBKDF2 uses PBKDF2-SHA256 for key derivation; FIPS-approved.
const (
	KDFScrypt KDF = "scrypt"
	KDFPBKDF2 KDF = "pbkdf2"
)

// scrypt cost parameters (interactive-grade) and pbkdf2 iteration count.
const (
	scryptN    = 1 << 16
	scryptR    = 8
	scryptP    = 1
	pbkdf2Iter = 600_000
	keyLen     = 32 // AES-256
)

// scryptNCap, scryptRCap, and scryptPCap bound the file-supplied scrypt cost
// parameters so a crafted or corrupt key file cannot trigger memory exhaustion
// on load. scrypt's working memory scales with both r (the 128*N*r block array)
// and p (the p*128*r buffer), so bounding N alone is insufficient — within
// scrypt's own r*p<2^30 limit an unbounded r or p still drives a multi-terabyte
// allocation. Each cap is well above the values we write (N=1<<16, r=8, p=1),
// leaving headroom for future cost increases while keeping the worst case
// finite.
const (
	scryptNCap = 1 << 20
	scryptRCap = 32
	scryptPCap = 16
)

// pbkdf2IterCap bounds the file-supplied PBKDF2 iteration count so a crafted or
// corrupt key file cannot drive an unbounded HMAC-SHA256 loop (a CPU DoS on
// load). It is far above the 600k we write while keeping the worst case to a
// few seconds rather than minutes.
const pbkdf2IterCap = 100_000_000

// ErrWrongPassword is returned when decryption authentication fails.
var ErrWrongPassword = errors.New("incorrect password or corrupt key file")

// encryptedKey is the on-disk container (polypkg.repo-key/v1). It stores only
// public material in cleartext (key id, KDF params); the Ed25519 seed is sealed
// with AES-256-GCM under a password-derived key.
type encryptedKey struct {
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

func deriveKey(kdf KDF, password string, salt []byte, ek *encryptedKey) ([]byte, error) {
	switch kdf {
	case KDFScrypt:
		return scrypt.Key([]byte(password), salt, ek.N, ek.R, ek.P, keyLen)
	case KDFPBKDF2:
		return pbkdf2.Key(sha256.New, password, salt, ek.Iter, keyLen)
	default:
		return nil, fmt.Errorf("unsupported kdf %q", kdf)
	}
}

// SaveKey encrypts kp's seed under password using kdf and writes a 0600 file.
func SaveKey(path string, kp *Keypair, password string, kdf KDF) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("salt: %w", err)
	}
	ek := &encryptedKey{Schema: "polypkg.repo-key/v1", KDF: string(kdf), Salt: base64.StdEncoding.EncodeToString(salt)}
	switch kdf {
	case KDFScrypt:
		ek.N, ek.R, ek.P = scryptN, scryptR, scryptP
	case KDFPBKDF2:
		ek.Iter = pbkdf2Iter
	default:
		return fmt.Errorf("unsupported kdf %q", kdf)
	}
	dk, err := deriveKey(kdf, password, salt, ek)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	id := kp.KeyID()
	ct := gcm.Seal(nil, nonce, kp.Seed(), id[:]) // bind key id as additional data
	ek.KeyID = hex.EncodeToString(id[:])
	ek.Nonce = base64.StdEncoding.EncodeToString(nonce)
	ek.Ciphertext = base64.StdEncoding.EncodeToString(ct)

	raw, err := json.MarshalIndent(ek, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return os.Rename(tmp, path)
}

// LoadKey reads and decrypts a key file, returning the reconstructed keypair.
func LoadKey(path, password string) (*Keypair, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is the key file location from the repo manifest; user controls key-dir
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	var ek encryptedKey
	if err := json.Unmarshal(raw, &ek); err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if ek.Schema != "polypkg.repo-key/v1" {
		return nil, fmt.Errorf("unexpected key schema %q", ek.Schema)
	}
	if KDF(ek.KDF) == KDFScrypt {
		if ek.N <= 1 {
			return nil, fmt.Errorf("scrypt cost N=%d is invalid (must be >1 and a power of two)", ek.N)
		}
		if ek.N > scryptNCap {
			return nil, fmt.Errorf("scrypt cost N=%d exceeds allowed maximum %d", ek.N, scryptNCap)
		}
		if ek.R <= 0 || ek.R > scryptRCap {
			return nil, fmt.Errorf("scrypt parameter r=%d is out of range (1..%d)", ek.R, scryptRCap)
		}
		if ek.P <= 0 || ek.P > scryptPCap {
			return nil, fmt.Errorf("scrypt parameter p=%d is out of range (1..%d)", ek.P, scryptPCap)
		}
	}
	if KDF(ek.KDF) == KDFPBKDF2 {
		if ek.Iter <= 0 || ek.Iter > pbkdf2IterCap {
			return nil, fmt.Errorf("pbkdf2 iteration count iter=%d is out of range (1..%d)", ek.Iter, pbkdf2IterCap)
		}
	}
	salt, err := base64.StdEncoding.DecodeString(ek.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	dk, err := deriveKey(KDF(ek.KDF), password, salt, &ek)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(ek.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(ek.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	idBytes, err := hex.DecodeString(ek.KeyID)
	if err != nil {
		return nil, fmt.Errorf("decode key id: %w", err)
	}
	if len(idBytes) != 8 {
		return nil, fmt.Errorf("decode key id: expected 8 bytes, got %d", len(idBytes))
	}
	seed, err := gcm.Open(nil, nonce, ct, idBytes)
	if err != nil {
		return nil, ErrWrongPassword
	}
	var id [8]byte
	copy(id[:], idBytes)
	return KeypairFromSeed(seed, id)
}
