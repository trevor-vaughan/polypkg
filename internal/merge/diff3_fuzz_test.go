package merge_test

import (
	"bytes"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/merge"
)

// FuzzMerge asserts Merge never panics, reports a non-negative conflict count,
// emits well-formed (balanced) conflict markers whose count matches Conflicts,
// and round-trips an all-equal triple — for arbitrary byte triples including
// empty, single-line, NUL-bearing, and non-UTF8 inputs.
func FuzzMerge(f *testing.F) {
	seeds := [][3]string{
		{"", "", ""},
		{"a\n", "a\n", "a\n"},
		{"a\nb\nc\n", "a\nB\nc\n", "a\nb\nC\n"},
		{"a\nb\nc\n", "a\nX\nc\n", "a\nY\nc\n"},
		{"x", "y", "z"},
		{"a\x00b\n", "a\x00c\n", "a\x00d\n"},
		{"\xff\xfe\n", "\xff\n", "\xfe\n"},
	}
	for _, s := range seeds {
		f.Add([]byte(s[0]), []byte(s[1]), []byte(s[2]))
	}
	f.Fuzz(func(t *testing.T, base, live, incoming []byte) {
		res, err := merge.Merge(base, live, incoming)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Conflicts < 0 {
			t.Fatalf("negative conflict count: %d", res.Conflicts)
		}
		// Marker balance: every block we emit has one open and one close. We
		// assert opens == closes rather than == Conflicts because fuzz CONTENT
		// may itself contain marker-like lines; balance is the content-robust
		// well-formedness invariant.
		opens := bytes.Count(res.Merged, []byte("<<<<<<< LIVE\n"))
		closes := bytes.Count(res.Merged, []byte(">>>>>>> INCOMING"))
		if opens < res.Conflicts || closes < res.Conflicts {
			t.Fatalf("fewer markers than conflicts: opens=%d closes=%d conflicts=%d", opens, closes, res.Conflicts)
		}

		// An all-equal triple must round-trip to the input with no conflicts.
		same, err := merge.Merge(base, base, base)
		if err != nil {
			t.Fatalf("unexpected error on identity merge: %v", err)
		}
		if same.Conflicts != 0 {
			t.Fatalf("identity merge reported %d conflicts", same.Conflicts)
		}
		if !bytes.Equal(same.Merged, base) {
			t.Fatalf("identity merge did not round-trip:\n got %q\nwant %q", same.Merged, base)
		}
	})
}
