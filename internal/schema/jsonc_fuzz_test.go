package schema

import (
	"strings"
	"testing"
)

func FuzzParseProfileJSONC(f *testing.F) {
	f.Add(`{
  "schema": "polypkg.spec/v1",
  "name": "minimal",
  "scopes": {"user": {"substrate": "store"}},
  "sources": {"order": ["native"], "native": {"type": "polypkg-native", "url": "https://e.invalid", "trust_root": "/k"}}
}`)
	f.Add(`{"schema":"polypkg.spec/v1"}`)
	f.Add(`// comment-only`)
	f.Add(``)
	f.Add(`{`)
	f.Add(`{"a": /* unterminated`)
	f.Fuzz(func(t *testing.T, s string) {
		// Must never panic; errors are fine.
		_, _ = ParseProfile(strings.NewReader(s), "profile.jsonc")
	})
}

func FuzzParsePackageJSONC(f *testing.F) {
	f.Add(`{
  "schema": "polypkg.package/v1",
  "name": "x",
  "version": "1.0.0",
  "actions": [{"phase":"install","action":"run","params":{"cmd":"echo hi"}}]
}`)
	f.Add(`{"schema":"polypkg.package/v1","name":"x","version":"1.0.0","actions":[{"phase":"install","action":"run","params":{"p":{"!starlark":"host.arch"}}}]}`)
	f.Add(`{`)
	f.Add(`// comment-only package`)
	f.Add(`{"actions":[{"params":{"p":{"!starlark":"x","extra":1}}}]}`)
	f.Fuzz(func(t *testing.T, s string) {
		// Must never panic; errors are fine.
		_, _ = ParsePackage(strings.NewReader(s), "polypkg.jsonc")
	})
}
