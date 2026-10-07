package archive_test

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/trevor-vaughan/polypkg/internal/archive"
)

// compressedTarFormats are the formats that wrap a tar stream in compression.
var compressedTarFormats = []archive.Format{archive.FormatTarGz, archive.FormatTarZst, archive.FormatTarXz}

// strictOptions returns valid PolicyStrict options for format.
func strictOptions(format archive.Format) archive.Options {
	opts := strictCase{}.options()
	opts.Format = format
	return opts
}

// extractData runs Extract over data into a fresh root and checks that
// nothing was written outside it.
func extractData(t *testing.T, data []byte, opts archive.Options) (*os.Root, []archive.Placed, error) {
	t.Helper()
	base, root := newTestRoot(t)
	placed, err := archive.Extract(bytes.NewReader(data), int64(len(data)), root, opts)
	assertNothingOutside(t, base)
	return root, placed, err
}

// noise returns n deterministic, incompressible bytes.
func noise(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.NewChaCha8([32]byte{1}).Read(b)
	return b
}

func TestExtractMatrix(t *testing.T) {
	for _, format := range allFormats {
		for _, c := range strictCases() {
			t.Run(format.String()+"/"+c.name, func(t *testing.T) {
				if why := fixtureUnexpressible(format, c.members); why != "" {
					t.Skip(why)
				}
				data := fixtureArchive(t, format, c.members...)
				checkStrictCase(t, c, func(root *os.Root, opts archive.Options) ([]archive.Placed, error) {
					opts.Format = format
					return archive.Extract(bytes.NewReader(data), int64(len(data)), root, opts)
				})
			})
		}
	}
}

func TestDetectRecognisesEveryFixtureFormat(t *testing.T) {
	for _, format := range allFormats {
		data := fixtureArchive(t, format, fixtureMember{name: "a", kind: fixtureFile, body: "a"})
		got, err := archive.Detect(data[:min(len(data), archive.DetectHeaderLen)])
		if err != nil || got != format {
			t.Errorf("Detect(%s fixture) = %s, %v", format, got, err)
		}
	}
}

func TestExtractRefusesNonTarPayload(t *testing.T) {
	payloads := map[string][]byte{
		"short text":       []byte("just a binary, not an archive\n"),
		"a block of text":  bytes.Repeat([]byte("not a tar header "), 64),
		"a compressed zip": fixtureZip(t, fixtureMember{name: "a", kind: fixtureFile, body: "a"}),
		"an empty stream":  nil,
	}
	for _, format := range compressedTarFormats {
		for name, payload := range payloads {
			t.Run(format.String()+"/"+name, func(t *testing.T) {
				_, _, err := extractData(t, fixtureCompress(t, format, payload), strictOptions(format))
				if err == nil || !strings.Contains(err.Error(), "-compressed but does not contain a tar archive") {
					t.Fatalf("error = %v, want the non-tar payload refusal", err)
				}
			})
		}
	}
	t.Run("tar/not a tar", func(t *testing.T) {
		_, _, err := extractData(t, bytes.Repeat([]byte("x"), 1024), strictOptions(archive.FormatTar))
		if err == nil || !strings.Contains(err.Error(), "archive is not a tar archive") {
			t.Fatalf("error = %v, want the not-a-tar refusal", err)
		}
	})
	t.Run("zip/not a zip", func(t *testing.T) {
		_, _, err := extractData(t, []byte("PK\x03\x04 but nothing else"), strictOptions(archive.FormatZip))
		if err == nil || !strings.Contains(err.Error(), "read zip archive") {
			t.Fatalf("error = %v, want the zip read failure", err)
		}
	})
}

func TestExtractEmptyTarPayload(t *testing.T) {
	empty := fixtureTar(t)
	for _, format := range append([]archive.Format{archive.FormatTar}, compressedTarFormats...) {
		t.Run(format.String(), func(t *testing.T) {
			_, placed, err := extractData(t, fixtureCompress(t, format, empty), strictOptions(format))
			if err != nil {
				t.Fatalf("extract an empty tar: %v", err)
			}
			if len(placed) != 0 {
				t.Fatalf("placed %+v from an empty tar", placed)
			}
		})
	}
}

func TestExtractRefusesTruncatedStreams(t *testing.T) {
	// "first" has a 512-byte header and 600 bytes of body padded to 1024, so
	// "second"'s header occupies bytes [1536, 2048).
	payload := fixtureTar(t,
		fixtureMember{name: "first", kind: fixtureFile, body: string(noise(600))},
		fixtureMember{name: "second", kind: fixtureFile, body: "second"},
	)
	cuts := map[string][]byte{
		"tar cut mid-header": payload[:1536+100],
		"tar cut mid-body":   payload[:512+300],
	}
	for _, format := range append([]archive.Format{archive.FormatTar}, compressedTarFormats...) {
		for name, cut := range cuts {
			t.Run(format.String()+"/"+name, func(t *testing.T) {
				_, _, err := extractData(t, fixtureCompress(t, format, cut), strictOptions(format))
				if err == nil {
					t.Fatal("extracting a truncated tar succeeded")
				}
			})
		}
	}
	for _, format := range append(append([]archive.Format{}, compressedTarFormats...), archive.FormatZip) {
		t.Run(format.String()+"/archive cut in half", func(t *testing.T) {
			data := fixtureArchive(t, format,
				fixtureMember{name: "first", kind: fixtureFile, body: string(noise(4096))},
				fixtureMember{name: "second", kind: fixtureFile, body: "second"},
			)
			_, _, err := extractData(t, data[:len(data)/2], strictOptions(format))
			if err == nil {
				t.Fatal("extracting a truncated archive succeeded")
			}
		})
	}
}

// lyingZip returns a zip whose single member "bomb" holds content but whose
// headers declare only declared bytes.
func lyingZip(t *testing.T, content []byte, declared uint64) []byte {
	t.Helper()
	var compressed bytes.Buffer
	fw, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fh := &zip.FileHeader{
		Name:               "bomb",
		Method:             zip.Deflate,
		CRC32:              crc32.ChecksumIEEE(content),
		CompressedSize64:   uint64(compressed.Len()),
		UncompressedSize64: declared,
	}
	fh.SetMode(0o644)
	w, err := zw.CreateRaw(fh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(compressed.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractZipCountsBytesNotDeclaredSizes(t *testing.T) {
	content := bytes.Repeat([]byte("A"), 1000)
	limits := archive.Limits{MaxFileBytes: 100, MaxTotalBytes: 1000, MaxEntries: 10}
	cases := map[string]struct {
		data    []byte
		wantErr string
	}{
		"declared size smaller than the content":          {lyingZip(t, content, 10), `"bomb"`},
		"declared size within the limit, content over it": {lyingZip(t, content, 50), `"bomb"`},
		"honest size over the limit":                      {lyingZip(t, content, uint64(len(content))), `"bomb" exceeds the per-file limit of 100 bytes`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			opts := strictOptions(archive.FormatZip)
			opts.Limits = limits
			root, _, err := extractData(t, c.data, opts)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error = %v, want one containing %q", err, c.wantErr)
			}
			if info, err := root.Lstat("bomb"); err == nil && info.Size() > limits.MaxFileBytes {
				t.Fatalf("wrote %d bytes of a member limited to %d", info.Size(), limits.MaxFileBytes)
			}
		})
	}
}

func TestExtractZipRefusesOversizedSymlinkTarget(t *testing.T) {
	data := fixtureZip(t, fixtureMember{name: "link", kind: fixtureSymlink, target: strings.Repeat("a", 4097)})
	_, _, err := extractData(t, data, strictOptions(archive.FormatZip))
	if err == nil || !strings.Contains(err.Error(), "target longer than 4096 bytes") {
		t.Fatalf("error = %v, want the oversized symlink target refusal", err)
	}
}

func TestExtractZipRequiresStrictPolicy(t *testing.T) {
	data := fixtureZip(t, fixtureMember{name: "a", kind: fixtureFile, body: "a"})
	opts := strictOptions(archive.FormatZip)
	opts.Policy = archive.PolicyPackage
	_, _, err := extractData(t, data, opts)
	if err == nil || !strings.Contains(err.Error(), "only be extracted with PolicyStrict") {
		t.Fatalf("error = %v, want the PolicyStrict requirement", err)
	}
}

func TestExtractRefusesUnknownFormat(t *testing.T) {
	data := fixtureTar(t, fixtureMember{name: "a", kind: fixtureFile, body: "a"})
	_, _, err := extractData(t, data, strictOptions(archive.Format(0)))
	if err == nil || !strings.Contains(err.Error(), "unsupported format Format(0)") {
		t.Fatalf("error = %v, want the unsupported format refusal", err)
	}
}

func TestExtractTarGzWithPackagePolicy(t *testing.T) {
	data := fixtureArchive(t, archive.FormatTarGz, fixtureMember{name: "polypkg.yaml", kind: fixtureFile, body: "name: demo\n"})
	opts := archive.Options{Format: archive.FormatTarGz, Policy: archive.PolicyPackage, Limits: archive.DefaultLimits(), DirPerm: 0o755}
	root, _, err := extractData(t, data, opts)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	got, err := root.ReadFile("polypkg.yaml")
	if err != nil || string(got) != "name: demo\n" {
		t.Fatalf("polypkg.yaml = %q, %v", got, err)
	}
}

func TestExtractCapsDecompressedBytes(t *testing.T) {
	members := []fixtureMember{
		{name: "skipped", kind: fixtureFile, body: string(make([]byte, 64<<10))},
		{name: "wanted", kind: fixtureFile, body: "x"},
	}
	// 1 KiB of content plus 8 KiB of framing for each of 2 entries.
	const budget = 1<<10 + 2*(8<<10)
	for _, format := range append([]archive.Format{archive.FormatTar}, compressedTarFormats...) {
		t.Run(format.String(), func(t *testing.T) {
			opts := strictOptions(format)
			opts.Limits = archive.Limits{MaxFileBytes: 1 << 10, MaxTotalBytes: 1 << 10, MaxEntries: 2}
			opts.Include = []string{"wanted"}
			_, _, err := extractData(t, fixtureArchive(t, format, members...), opts)
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("decompressed archive exceeds %d bytes", budget)) {
				t.Fatalf("error = %v, want the decompressed-size refusal", err)
			}
		})
	}
}

// TestExtractStreamBudgetSaturates pins that a huge MaxEntries saturates the
// decompressed-stream budget instead of wrapping. 2^51+1 entries times the
// 8 KiB framing allowance wraps to 8 KiB, which would refuse the 64 KiB
// skipped member below.
func TestExtractStreamBudgetSaturates(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("MaxEntries cannot hold 2^51 on this platform")
	}
	shift := 51
	members := []fixtureMember{
		{name: "skipped", kind: fixtureFile, body: string(noise(64 << 10))},
		{name: "wanted", kind: fixtureFile, body: "x"},
	}
	for _, format := range append([]archive.Format{archive.FormatTar}, compressedTarFormats...) {
		t.Run(format.String(), func(t *testing.T) {
			opts := strictOptions(format)
			opts.Limits = archive.Limits{MaxFileBytes: 1 << 10, MaxTotalBytes: 1 << 10, MaxEntries: 1<<shift + 1}
			opts.Include = []string{"wanted"}
			_, placed, err := extractData(t, fixtureArchive(t, format, members...), opts)
			if err != nil {
				t.Fatalf("extract: %v", err)
			}
			if len(placed) != 1 || placed[0].Path != "wanted" {
				t.Fatalf("placed %+v, want only wanted", placed)
			}
		})
	}
}

func TestExtractChecksPackageOptionsBeforeReading(t *testing.T) {
	data := fixtureArchive(t, archive.FormatTarGz, fixtureMember{name: "a", kind: fixtureFile, body: "a"})
	opts := archive.Options{Format: archive.FormatTarGz, Policy: archive.PolicyPackage, DirPerm: 0o755}
	_, _, err := extractData(t, data, opts)
	if err == nil || !strings.Contains(err.Error(), "extraction limits must be positive") {
		t.Fatalf("error = %v, want the invalid Limits refusal", err)
	}
}

func TestExtractChecksStrictOptionsBeforeReading(t *testing.T) {
	for _, format := range allFormats {
		t.Run(format.String(), func(t *testing.T) {
			opts := strictOptions(format)
			opts.Limits = archive.Limits{}
			data := fixtureArchive(t, format, fixtureMember{name: "a", kind: fixtureFile, body: "a"})
			_, _, err := extractData(t, data, opts)
			if err == nil || !strings.Contains(err.Error(), "every Limits field must be positive") {
				t.Fatalf("error = %v, want the invalid Limits refusal", err)
			}
		})
	}
}

// TestExtractRefusesHugeZstdWindow pins the decoder's window cap: this 9-byte
// frame declares a 512 MiB window, which the library default would allocate
// before reading any content.
func TestExtractRefusesHugeZstdWindow(t *testing.T) {
	frame := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x98, 0x01, 0x00, 0x00}
	_, _, err := extractData(t, frame, strictOptions(archive.FormatTarZst))
	if !errors.Is(err, zstd.ErrWindowSizeExceeded) {
		t.Fatalf("error = %v, want %v", err, zstd.ErrWindowSizeExceeded)
	}
}

// TestExtractZipCountsEntriesUpFront pins that a zip whose central directory
// lists more members than MaxEntries is refused before any member is written.
func TestExtractZipCountsEntriesUpFront(t *testing.T) {
	data := fixtureZip(t,
		fixtureMember{name: "a", kind: fixtureFile, body: "a"},
		fixtureMember{name: "b", kind: fixtureFile, body: "b"},
		fixtureMember{name: "c", kind: fixtureFile, body: "c"},
	)
	opts := strictOptions(archive.FormatZip)
	opts.Limits.MaxEntries = 2
	root, _, err := extractData(t, data, opts)
	if err == nil || !strings.Contains(err.Error(), "exceeds 2 entries (the zip lists 3 members)") {
		t.Fatalf("error = %v, want the up-front entry refusal", err)
	}
	ents, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("wrote %d entries before refusing the archive", len(ents))
	}
}
