package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootVersionFlagWithBuildInfo(t *testing.T) {
	oldCommit, oldDate := Commit, Date
	Commit, Date = "abc1234", "2026-06-27"
	t.Cleanup(func() { Commit, Date = oldCommit, oldDate })

	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute --version: %v", err)
	}

	got := strings.TrimSpace(out.String())
	want := "polypkg " + Version + " (abc1234, 2026-06-27)"
	if got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

func TestRootVersionFlagBare(t *testing.T) {
	oldCommit, oldDate := Commit, Date
	Commit, Date = "unknown", "unknown"
	t.Cleanup(func() { Commit, Date = oldCommit, oldDate })

	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute --version: %v", err)
	}

	got := strings.TrimSpace(out.String())
	want := "polypkg " + Version
	if got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

// A build where only one of Commit/Date was stamped must not leak the literal
// "unknown" placeholder; it falls back to the bare form.
func TestRootVersionFlagPartialStampFallsBackToBare(t *testing.T) {
	oldCommit, oldDate := Commit, Date
	Commit, Date = "abc1234", "unknown"
	t.Cleanup(func() { Commit, Date = oldCommit, oldDate })

	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute --version: %v", err)
	}

	got := strings.TrimSpace(out.String())
	want := "polypkg " + Version
	if got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}
