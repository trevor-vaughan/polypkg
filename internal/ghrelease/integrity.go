package ghrelease

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Integrity sources CheckIntegrity reports: what the downloaded bytes were
// checked against.
const (
	IntegrityGitHubDigest  = "github-digest"
	IntegrityChecksumsFile = "checksums-file"
	IntegrityUnverified    = "UNVERIFIED"
)

// ErrUnverifiable is wrapped by CheckIntegrity's error when an asset has no
// GitHub digest and the release has no checksums file, and the caller did
// not accept unverified assets.
var ErrUnverifiable = errors.New("the release offers neither a GitHub digest nor a checksums file to verify it against")

// IntegrityError reports downloaded bytes whose sha256 differs from the
// value the release published for them. It is a tamper or corruption
// signal, so it refuses the whole import.
type IntegrityError struct {
	Asset  string // asset file name
	Source string // IntegrityGitHubDigest or IntegrityChecksumsFile
	Want   string // published sha256, lower-case hex
	Got    string // sha256 of the downloaded bytes, lower-case hex
}

func (e *IntegrityError) Error() string {
	return fmt.Sprintf("release asset %q failed its %s check: downloaded sha256 %s, published sha256 %s",
		e.Asset, e.Source, e.Got, e.Want)
}

// CheckIntegrity verifies data, the downloaded bytes of a, and returns the
// source it was checked against:
//
//   - a.Digest, when GitHub reports one, must match (IntegrityGitHubDigest);
//   - else sums, the parsed checksums file (nil when the release has none),
//     must list a.Name with a matching sum (IntegrityChecksumsFile);
//   - else the asset is IntegrityUnverified when insecureSkip is set, and an
//     error wrapping ErrUnverifiable when it is not.
//
// A mismatch is an *IntegrityError whatever insecureSkip says: that flag only
// admits an asset nothing vouches for, never one that contradicts what the
// release published. A missing checksums entry is an error for the same
// reason.
func CheckIntegrity(a Asset, data []byte, sums map[string]string, insecureSkip bool) (string, error) {
	h := sha256.Sum256(data)
	got := hex.EncodeToString(h[:])
	if a.Digest != "" {
		want, ok := strings.CutPrefix(a.Digest, "sha256:")
		want = strings.ToLower(want)
		if !ok || !isSHA256Hex(want) {
			return "", fmt.Errorf("release asset %q: GitHub reports digest %q, which is not sha256:<64 hex digits>", a.Name, a.Digest)
		}
		if want != got {
			return "", &IntegrityError{Asset: a.Name, Source: IntegrityGitHubDigest, Want: want, Got: got}
		}
		return IntegrityGitHubDigest, nil
	}
	if sums != nil {
		want, ok := sums[a.Name]
		if !ok {
			return "", fmt.Errorf("release asset %q has no entry in the release's checksums file", a.Name)
		}
		if want = strings.ToLower(want); want != got {
			return "", &IntegrityError{Asset: a.Name, Source: IntegrityChecksumsFile, Want: want, Got: got}
		}
		return IntegrityChecksumsFile, nil
	}
	if insecureSkip {
		return IntegrityUnverified, nil
	}
	return "", fmt.Errorf("release asset %q: %w", a.Name, ErrUnverifiable)
}
