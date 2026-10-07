package repo

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestEntryRulesAdmit(t *testing.T) {
	type decl struct{ version, plat, src string }
	cases := []struct {
		name    string
		prior   []decl   // each must be admitted
		next    decl     // the declaration under test
		wantErr []string // substrings of the refusal; nil means next is admitted
	}{
		{
			name:  "distinct platforms share a version",
			prior: []decl{{"1.0.0", "linux/amd64", "./a"}},
			next:  decl{"1.0.0", "darwin/arm64", "./b"},
		},
		{
			name:  "agnostic and platform entries at different versions",
			prior: []decl{{"1.0.0", "", "./a"}},
			next:  decl{"2.0.0", "linux/amd64", "./b"},
		},
		{
			name:    "duplicate platform-agnostic version",
			prior:   []decl{{"1.0.0", "", "./a"}},
			next:    decl{"1.0.0", "", "./b"},
			wantErr: []string{`"hello"`, "1.0.0", "declared twice", "./a", "./b"},
		},
		{
			name:    "duplicate version and platform",
			prior:   []decl{{"1.0.0", "linux/amd64", "./a"}},
			next:    decl{"1.0.0", "linux/amd64", "./b"},
			wantErr: []string{`"hello"`, "1.0.0", "linux/amd64", "declared twice", "./a", "./b"},
		},
		{
			name:    "platform entry after a platform-agnostic one",
			prior:   []decl{{"1.0.0", "", "./a"}},
			next:    decl{"1.0.0", "linux/amd64", "./b"},
			wantErr: []string{"1.0.0", "platform-agnostic entry (./a)", "linux/amd64 entry (./b)"},
		},
		{
			name:    "platform-agnostic entry after platform entries names the first platform in sorted order",
			prior:   []decl{{"1.0.0", "linux/amd64", "./a"}, {"1.0.0", "darwin/arm64", "./b"}},
			next:    decl{"1.0.0", "", "./c"},
			wantErr: []string{"1.0.0", "platform-agnostic entry (./c)", "darwin/arm64 entry (./b)"},
		},
		{
			name:    "semver-equal spellings of a platform-agnostic version",
			prior:   []decl{{"1.0", "", "./a"}},
			next:    decl{"1.0.0", "", "./b"},
			wantErr: []string{`"hello"`, "1.0.0", "declared twice", "./a (as 1.0)", "./b"},
		},
		{
			name:    "spellings that differ only in build metadata on one platform",
			prior:   []decl{{"1.0.0+a", "linux/amd64", "./a"}},
			next:    decl{"1.0.0+b", "linux/amd64", "./b"},
			wantErr: []string{"1.0.0+b", "linux/amd64", "declared twice", "./a (as 1.0.0+a)", "./b"},
		},
		{
			name:    "a platform entry semver-equal to a platform-agnostic one",
			prior:   []decl{{"1.0", "", "./a"}},
			next:    decl{"1.0.0", "linux/amd64", "./b"},
			wantErr: []string{"platform-agnostic entry (./a (as 1.0))", "linux/amd64 entry (./b)"},
		},
		{
			name:  "semver-equal spellings on distinct platforms",
			prior: []decl{{"1.0", "linux/amd64", "./a"}},
			next:  decl{"1.0.0", "darwin/arm64", "./b"},
		},
		{
			name:  "a prerelease is its own version",
			prior: []decl{{"1.0.0-rc.1", "", "./a"}},
			next:  decl{"1.0.0", "", "./b"},
		},
		{
			name:    "not a semantic version",
			next:    decl{"latest", "", "./a"},
			wantErr: []string{`package "hello" version "latest" is not a semantic version`},
		},
		{
			name:    "allow-list typo",
			next:    decl{"1.0.0", "linux/amd46", "./a"},
			wantErr: []string{`declares platform "linux/amd46"`},
		},
		{
			name:    "variant segment is not publishable yet",
			next:    decl{"1.0.0", "linux/arm/v7", "./a"},
			wantErr: []string{`declares platform "linux/arm/v7"`},
		},
		{
			name:    "upper-case segment",
			next:    decl{"1.0.0", "Linux/amd64", "./a"},
			wantErr: []string{`declares platform "Linux/amd64"`},
		},
		{
			name:    "reserved any token",
			next:    decl{"1.0.0", "any", "./a"},
			wantErr: []string{`declares platform "any"`},
		},
		{
			name:    "traversal-shaped platform",
			next:    decl{"1.0.0", "../../etc", "./a"},
			wantErr: []string{`declares platform "../../etc"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := entryRules{name: "hello"}
			for _, d := range tc.prior {
				if err := r.admit(d.version, d.plat, d.src, false); err != nil {
					t.Fatalf("prior admit(%+v): %v", d, err)
				}
			}
			err := r.admit(tc.next.version, tc.next.plat, tc.next.src, false)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("admit(%+v) = %v, want nil", tc.next, err)
				}
				return
			}
			var pe *PublishError
			if !errors.As(err, &pe) {
				t.Fatalf("admit(%+v) = %v (%T), want *PublishError", tc.next, err, err)
			}
			if pe.Hint == "" {
				t.Fatalf("refusal %q carries no hint", err)
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("refusal %q does not mention %q", err, want)
				}
			}
		})
	}
}

// TestEntryRulesDuplicateHintsPointAtManifestEdit pins that neither duplicate
// hint tells the operator to run `repo remove name@version` alone: that
// withdraws every entry at the version, not one of the duplicates.
func TestEntryRulesDuplicateHintsPointAtManifestEdit(t *testing.T) {
	for _, plat := range []string{"", "linux/amd64"} {
		r := entryRules{name: "hello"}
		if err := r.admit("1.0.0", plat, "./a", false); err != nil {
			t.Fatal(err)
		}
		err := r.admit("1.0.0", plat, "./b", false)
		var pe *PublishError
		if !errors.As(err, &pe) {
			t.Fatalf("platform %q: admit = %v, want *PublishError", plat, err)
		}
		for _, want := range []string{"`polypkg repo remove hello@1.0.0` withdraws every", "delete", "from polypkg-repo.yaml"} {
			if !strings.Contains(pe.Hint, want) {
				t.Fatalf("platform %q: hint %q does not mention %q", plat, pe.Hint, want)
			}
		}
	}
}

// TestEntryRulesRecordsNothingOnRefusal pins that a refused declaration leaves
// no trace: a later, valid declaration for the same version is judged as if
// the refused one never happened.
func TestEntryRulesRecordsNothingOnRefusal(t *testing.T) {
	r := entryRules{name: "hello"}
	if err := r.admit("1.0.0", "linux/amd46", "./a", false); err == nil {
		t.Fatal("admit accepted linux/amd46; want a producer-validation refusal")
	}
	if err := r.admit("1.0.0", "", "./b", false); err != nil {
		t.Fatalf("the refused linux/amd46 entry was recorded: %v", err)
	}
}

// TestEntryRulesAdmitsManyVersionsInLinearTime pins that admitting a version
// does not compare it with every earlier one: 100 000 versions take well under
// a second, where a pairwise check takes minutes.
func TestEntryRulesAdmitsManyVersionsInLinearTime(t *testing.T) {
	r := entryRules{name: "hello"}
	start := time.Now()
	for i := range 100_000 {
		if err := r.admit(fmt.Sprintf("1.%d.0", i), "", "./src", false); err != nil {
			t.Fatalf("version 1.%d.0: %v", i, err)
		}
	}
	err := r.admit("1.0", "", "./dup", false)
	if err == nil || !strings.Contains(err.Error(), "./src (as 1.0.0) and ./dup") {
		t.Fatalf("admit(1.0) = %v, want the duplicate of 1.0.0 named", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("admitting 100 000 versions took %v", elapsed)
	}
}
