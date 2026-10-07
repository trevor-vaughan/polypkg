package archive_test

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/archive"
)

// TestListMatrix proves List reports exactly what Extract places, in the same
// order and with the same refusals, for every strict scenario in every format.
func TestListMatrix(t *testing.T) {
	for _, format := range allFormats {
		for _, c := range strictCases() {
			t.Run(format.String()+"/"+c.name, func(t *testing.T) {
				if why := fixtureUnexpressible(format, c.members); why != "" {
					t.Skip(why)
				}
				data := fixtureArchive(t, format, c.members...)
				opts := c.options()
				opts.Format = format
				got, err := archive.List(bytes.NewReader(data), int64(len(data)), opts)
				if c.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), c.wantErr) {
						t.Fatalf("error = %v, want one containing %q", err, c.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				want := make([]archive.Member, len(c.want))
				for i, p := range c.want {
					want[i] = archive.Member{Path: p.Path, Kind: p.Kind, Mode: p.Mode}
				}
				if !slices.Equal(got, want) {
					t.Fatalf("members:\n got %+v\nwant %+v", got, want)
				}
			})
		}
	}
}

func TestListRequiresStrictPolicy(t *testing.T) {
	data := fixtureArchive(t, archive.FormatTar, fixtureMember{name: "a", kind: fixtureFile, body: "a"})
	opts := archive.Options{Format: archive.FormatTar, Policy: archive.PolicyPackage, Limits: testLimits, DirPerm: testDirPerm}
	_, err := archive.List(bytes.NewReader(data), int64(len(data)), opts)
	if err == nil || !strings.Contains(err.Error(), "List supports only PolicyStrict") {
		t.Fatalf("error = %v, want a PolicyStrict refusal", err)
	}
}

func TestListRefusesUnknownFormat(t *testing.T) {
	data := fixtureArchive(t, archive.FormatTar, fixtureMember{name: "a", kind: fixtureFile, body: "a"})
	opts := archive.Options{Policy: archive.PolicyStrict, Limits: testLimits, DirPerm: testDirPerm}
	_, err := archive.List(bytes.NewReader(data), int64(len(data)), opts)
	if err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Fatalf("error = %v, want an unsupported-format refusal", err)
	}
}

func TestListChecksOptionsBeforeReading(t *testing.T) {
	opts := archive.Options{Format: archive.FormatTar, Policy: archive.PolicyStrict, Limits: testLimits, DirPerm: 0o055}
	_, err := archive.List(bytes.NewReader(nil), 0, opts)
	if err == nil || !strings.Contains(err.Error(), "DirPerm") {
		t.Fatalf("error = %v, want a DirPerm refusal", err)
	}
}
