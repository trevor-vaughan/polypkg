package archive_test

import (
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/archive"
)

// tarHead returns a header-sized block carrying magic at the ustar offset.
func tarHead(magic string) []byte {
	head := make([]byte, 512)
	copy(head[257:], magic)
	return head
}

func TestDetect(t *testing.T) {
	cases := []struct {
		name string
		head []byte
		want archive.Format
	}{
		{"gzip", []byte{0x1f, 0x8b, 0x08, 0x00}, archive.FormatTarGz},
		{"zstd", []byte{0x28, 0xb5, 0x2f, 0xfd, 0x04}, archive.FormatTarZst},
		{"xz", []byte{0xfd, '7', 'z', 'X', 'Z', 0x00, 0x00, 0x04}, archive.FormatTarXz},
		{"zip with members", []byte("PK\x03\x04\x14\x00"), archive.FormatZip},
		{"empty zip", []byte("PK\x05\x06\x00\x00"), archive.FormatZip},
		{"POSIX tar", tarHead("ustar\x0000"), archive.FormatTar},
		{"GNU tar", tarHead("ustar  \x00"), archive.FormatTar},
		{"tar head of exactly DetectHeaderLen bytes", tarHead("ustar")[:archive.DetectHeaderLen], archive.FormatTar},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := archive.Detect(c.head)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if got != c.want {
				t.Fatalf("Detect = %s, want %s", got, c.want)
			}
		})
	}
}

func TestDetectRefusesUnsupportedContent(t *testing.T) {
	cases := map[string][]byte{
		"empty":                 nil,
		"shell script":          []byte("#!/bin/sh\necho hello\n"),
		"ELF binary":            []byte("\x7fELF\x02\x01\x01\x00"),
		"bzip2":                 []byte("BZh91AY&SY"),
		"7z":                    {'7', 'z', 0xbc, 0xaf, 0x27, 0x1c},
		"partial xz magic":      {0xfd, '7', 'z'},
		"tar magic cut short":   tarHead("ustar")[:archive.DetectHeaderLen-1],
		"magic one byte late":   tarHead("\x00ustar"),
		"zip spanning marker":   []byte("PK\x07\x08"),
		"gzip magic at offset1": {0x00, 0x1f, 0x8b},
	}
	for name, head := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := archive.Detect(head)
			if err == nil {
				t.Fatalf("Detect = %s, want an error", got)
			}
			if !strings.Contains(err.Error(), "not a supported archive") {
				t.Fatalf("error %q does not say the content is not a supported archive", err)
			}
		})
	}
}

func TestFormatString(t *testing.T) {
	cases := map[archive.Format]string{
		archive.FormatTarGz:  "tar.gz",
		archive.FormatTarZst: "tar.zst",
		archive.FormatTarXz:  "tar.xz",
		archive.FormatZip:    "zip",
		archive.FormatTar:    "tar",
		archive.Format(0):    "Format(0)",
	}
	for f, want := range cases {
		if got := f.String(); got != want {
			t.Errorf("Format(%d).String() = %q, want %q", int(f), got, want)
		}
	}
}
