package archive

import (
	"bytes"
	"errors"
	"fmt"
)

// Format is an archive container format. It is identified from the archive's
// leading bytes (see Detect), never from its file name.
type Format int

// The supported formats. The zero Format is none of them, so Options whose
// Format was never set are refused rather than guessed at.
const (
	FormatTarGz Format = iota + 1
	FormatTarZst
	FormatTarXz
	FormatZip
	FormatTar
)

// DetectHeaderLen is how many leading bytes Detect needs to recognise every
// format: a plain tar's "ustar" magic ends at this offset.
const DetectHeaderLen = 262

// ustarOffset is where POSIX and GNU tar headers carry their "ustar" magic.
const ustarOffset = 257

var (
	gzipMagic     = []byte{0x1f, 0x8b}
	zstdMagic     = []byte{0x28, 0xb5, 0x2f, 0xfd}
	xzMagic       = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}
	zipMagic      = []byte{'P', 'K', 0x03, 0x04}
	zipEmptyMagic = []byte{'P', 'K', 0x05, 0x06}
)

// String returns the format's conventional file-name suffix, e.g. "tar.gz".
func (f Format) String() string {
	switch f {
	case FormatTarGz:
		return "tar.gz"
	case FormatTarZst:
		return "tar.zst"
	case FormatTarXz:
		return "tar.xz"
	case FormatZip:
		return "zip"
	case FormatTar:
		return "tar"
	default:
		return fmt.Sprintf("Format(%d)", int(f))
	}
}

// Detect identifies an archive's format from its first bytes; pass at least
// DetectHeaderLen of them when the file is that long. Only magic numbers are
// consulted. A compression magic says nothing about the payload: Extract
// separately refuses a compressed stream that does not hold a tar archive.
func Detect(head []byte) (Format, error) {
	switch {
	case bytes.HasPrefix(head, gzipMagic):
		return FormatTarGz, nil
	case bytes.HasPrefix(head, zstdMagic):
		return FormatTarZst, nil
	case bytes.HasPrefix(head, xzMagic):
		return FormatTarXz, nil
	case bytes.HasPrefix(head, zipMagic), bytes.HasPrefix(head, zipEmptyMagic):
		return FormatZip, nil
	case isUstar(head):
		return FormatTar, nil
	}
	return 0, errors.New("not a supported archive: the content is not tar.gz, tar.zst, tar.xz, zip or tar")
}

// isUstar reports whether head carries the POSIX/GNU tar magic.
func isUstar(head []byte) bool {
	return len(head) >= DetectHeaderLen && string(head[ustarOffset:DetectHeaderLen]) == "ustar"
}
