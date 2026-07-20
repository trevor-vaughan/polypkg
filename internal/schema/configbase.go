package schema

import "strings"

// ConfigBaseRelPath returns the path, relative to a generation directory, at
// which the content-addressed config-base snapshot for hash is stored. hash is a
// "blake3:<hex>" digest; the algorithm prefix is stripped for the on-disk name
// and the first two hex characters form a fan-out subdirectory.
func ConfigBaseRelPath(hash string) string {
	hex := hash
	if i := strings.IndexByte(hash, ':'); i >= 0 {
		hex = hash[i+1:]
	}
	prefix := hex
	if len(hex) >= 2 {
		prefix = hex[:2]
	}
	return "config-base/" + prefix + "/" + hex
}
