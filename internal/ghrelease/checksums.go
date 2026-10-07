package ghrelease

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// MaxChecksumsSize caps a checksums asset: the importer downloads it with
// this limit, and ParseChecksums refuses anything larger.
const MaxChecksumsSize = 1 << 20

// utf8BOM is the byte-order mark some Windows tools write at the start of a
// text file.
const utf8BOM = "\ufeff"

// reChecksumsName matches a release-wide checksums asset: "checksums.txt",
// "gh_2.60.1_checksums.txt", "SHA256SUMS", jq's "sha256sum.txt". The name
// must start at a separator so "mychecksums.txt" is not one.
var reChecksumsName = regexp.MustCompile(`(?i)(^|[-_.])(sha256sums?|checksums?)(\.txt)?$`)

// FindChecksums returns the release asset that lists forAsset's sha256: the
// per-asset "<forAsset>.sha256" when the release has one, else a release-wide
// checksums asset. With several, the one whose name shares the longest
// prefix with forAsset wins, so a release shipping several tools verifies
// each against its own file; equal prefixes fall back to the lowest name.
// The bool is false when the release has neither.
func FindChecksums(assets []Asset, forAsset string) (Asset, bool) {
	var shared []Asset
	for _, a := range assets {
		if a.Name == forAsset+".sha256" {
			return a, true
		}
		if reChecksumsName.MatchString(a.Name) {
			shared = append(shared, a)
		}
	}
	if len(shared) == 0 {
		return Asset{}, false
	}
	return slices.MinFunc(shared, func(x, y Asset) int {
		if c := commonPrefixLen(y.Name, forAsset) - commonPrefixLen(x.Name, forAsset); c != 0 {
			return c
		}
		return strings.Compare(x.Name, y.Name)
	}), true
}

// commonPrefixLen returns the number of leading bytes a and b share.
func commonPrefixLen(a, b string) int {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// ParseChecksums parses a sha256sum-style checksums file: one
// "<64 hex digits> <name>" (text mode) or "<64 hex digits> *<name>" (binary
// mode) entry per line, with blank lines, CRLF endings and a leading UTF-8
// byte-order mark tolerated. A leading "./" on a name is stripped. It returns file name → lower-case hex
// sha256. The file is untrusted release
// content, so any malformed line, a name listed twice with different sums,
// an empty file, or one over MaxChecksumsSize is an error rather than a
// partial result.
func ParseChecksums(b []byte) (map[string]string, error) {
	if len(b) > MaxChecksumsSize {
		return nil, fmt.Errorf("checksums file is %d bytes, over the %d-byte limit", len(b), MaxChecksumsSize)
	}
	sums := make(map[string]string)
	for i, line := range strings.Split(strings.TrimPrefix(string(b), utf8BOM), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		if len(line) < 67 || line[64] != ' ' || (line[65] != ' ' && line[65] != '*') {
			return nil, fmt.Errorf("checksums line %d is not \"<sha256> <name>\" or \"<sha256> *<name>\"", i+1)
		}
		sum := strings.ToLower(line[:64])
		if !isSHA256Hex(sum) {
			return nil, fmt.Errorf("checksums line %d: the sha256 is not 64 hex digits", i+1)
		}
		// "sha256sum ./*" output names "./<file>"; only that prefix is
		// dropped, so "dir/<file>" never stands in for a release asset.
		name := strings.TrimPrefix(line[66:], "./")
		if name == "" {
			return nil, fmt.Errorf("checksums line %d names no file", i+1)
		}
		if prev, dup := sums[name]; dup && prev != sum {
			return nil, fmt.Errorf("checksums line %d lists %q again with a different sha256", i+1, name)
		}
		sums[name] = sum
	}
	if len(sums) == 0 {
		return nil, errors.New("checksums file has no entries")
	}
	return sums, nil
}

// isSHA256Hex reports whether s is exactly 64 hex digits.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// ChecksumsFor parses b, the bytes of file, which FindChecksums returned
// for forAsset. A per-asset "<forAsset>.sha256" file may hold only the bare
// sha256, surrounded by whitespace at most; the name is implied by the
// file's own, so that sum is returned as forAsset's. Anything else, and
// every release-wide checksums file, must be in ParseChecksums' format and
// list forAsset: a file without its entry is an error naming both.
func ChecksumsFor(file Asset, forAsset string, b []byte) (map[string]string, error) {
	if file.Name == forAsset+".sha256" && len(b) <= MaxChecksumsSize {
		bare := strings.TrimSpace(strings.TrimPrefix(string(b), utf8BOM))
		if sum := strings.ToLower(bare); isSHA256Hex(sum) {
			return map[string]string{forAsset: sum}, nil
		}
	}
	sums, err := ParseChecksums(b)
	if err != nil {
		return nil, err
	}
	if _, ok := sums[forAsset]; !ok {
		return nil, fmt.Errorf("checksums file %q has no entry for release asset %q", file.Name, forAsset)
	}
	return sums, nil
}
