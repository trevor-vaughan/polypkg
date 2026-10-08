package archive_test

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/trevor-vaughan/polypkg/internal/archive"
)

// allFormats lists every supported format, for tests that cover them all.
var allFormats = []archive.Format{
	archive.FormatTar, archive.FormatTarGz, archive.FormatTarZst, archive.FormatTarXz, archive.FormatZip,
}

// fixtureArchive encodes members as a complete archive in format.
func fixtureArchive(tb testing.TB, format archive.Format, members ...fixtureMember) []byte {
	tb.Helper()
	if format == archive.FormatZip {
		return fixtureZip(tb, members...)
	}
	return fixtureCompress(tb, format, fixtureTar(tb, members...))
}

// fixtureCompress wraps payload in format's compression. FormatTar returns it
// unchanged.
func fixtureCompress(tb testing.TB, format archive.Format, payload []byte) []byte {
	tb.Helper()
	var (
		buf bytes.Buffer
		w   io.WriteCloser
		err error
	)
	switch format {
	case archive.FormatTar:
		return payload
	case archive.FormatTarGz:
		w = gzip.NewWriter(&buf)
	case archive.FormatTarZst:
		w, err = zstd.NewWriter(&buf)
	case archive.FormatTarXz:
		w, err = xz.NewWriter(&buf)
	default:
		tb.Fatalf("fixtureCompress: %s is not a compressed tar format", format)
	}
	if err != nil {
		tb.Fatalf("%s writer: %v", format, err)
	}
	if _, err := w.Write(payload); err != nil {
		tb.Fatalf("%s write: %v", format, err)
	}
	if err := w.Close(); err != nil {
		tb.Fatalf("%s close: %v", format, err)
	}
	return buf.Bytes()
}

// fixtureZip encodes members as a zip archive, recording each member's type
// in its Unix external attributes the way Info-ZIP does.
func fixtureZip(tb testing.TB, members ...fixtureMember) []byte {
	tb.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range members {
		fh := &zip.FileHeader{Name: m.name, Method: zip.Deflate}
		body := m.body
		switch m.kind {
		case fixtureFile:
			fh.SetMode(m.fileMode())
		case fixtureDir:
			if !strings.HasSuffix(fh.Name, "/") {
				fh.Name += "/"
			}
			fh.SetMode(fs.ModeDir | m.fileMode())
		case fixtureSymlink:
			fh.SetMode(fs.ModeSymlink | m.fileMode())
			body = m.target
		case fixtureChar:
			fh.SetMode(fs.ModeDevice | fs.ModeCharDevice | m.fileMode())
		case fixtureBlock:
			fh.SetMode(fs.ModeDevice | m.fileMode())
		case fixtureFIFO:
			fh.SetMode(fs.ModeNamedPipe | m.fileMode())
		case fixtureSocket:
			fh.SetMode(fs.ModeSocket | m.fileMode())
		default:
			tb.Fatalf("fixtureZip: a %s member cannot be expressed in zip", m.kind)
		}
		w, err := zw.CreateHeader(fh)
		if err != nil {
			tb.Fatalf("zip header %q: %v", m.name, err)
		}
		if _, err := io.WriteString(w, body); err != nil {
			tb.Fatalf("zip body %q: %v", m.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		tb.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}
