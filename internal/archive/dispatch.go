package archive

import (
	"archive/zip"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"

	"github.com/klauspost/compress/zstd"
)

// tarBlockSize is the size of a tar header block. Every tar stream, even an
// empty one, starts with a full block.
const tarBlockSize = 512

// maxZstdWindow bounds the window a zstd frame may declare, and so the
// decoder's history buffer. zstd -19 uses 8 MiB; --long=26 needs 64 MiB.
const maxZstdWindow = 64 << 20

// tarEntryOverhead is the decompressed-stream allowance per entry for tar
// framing (header block, padding, pax and GNU long-name records) on top of
// Limits.MaxTotalBytes of content. 8 KiB covers a header block, a pax
// record or GNU long-name entry for a name of up to 4096 bytes (the longest
// strict extraction accepts) and the padding around them.
const tarEntryOverhead = 8 << 10

// Extract extracts the archive held in ra (size bytes long) into root, in the
// format opts.Format, normally chosen by Detect. Tar formats are decompressed
// and walked by ExtractTar; zip is read from its central directory and needs
// PolicyStrict. Under PolicyStrict a refusal can leave a partial tree in root:
// extract into an empty directory and discard it on error.
func Extract(ra io.ReaderAt, size int64, root *os.Root, opts Options) ([]Placed, error) {
	// Options are checked before decompressing, so bad ones are reported as
	// such rather than as a stream that overran a zero limit.
	var err error
	if opts.Policy == PolicyStrict {
		err = checkStrictOptions(opts)
	} else {
		err = opts.validate()
	}
	if err != nil {
		return nil, err
	}
	return walkArchive(ra, size, root, opts)
}

// Member is one filesystem object List reports: what Extract would place at
// Path under the same Options.
type Member struct {
	Path string      // slash-separated, relative to the extraction root
	Kind string      // KindFile, KindDir or KindSymlink
	Mode fs.FileMode // the mode Extract would set; zero for a symlink
}

// List reports what Extract would place for the archive held in ra (size
// bytes long) under opts — the same members, in the same order, with the same
// refusals — without writing anything. opts.Policy must be PolicyStrict. Every
// member is decompressed and read, so the per-file, total and entry limits
// apply exactly as they do to Extract, and paths are reported after
// StripComponents and Include. Implicitly created parent directories are
// reported as Extract reports them.
func List(ra io.ReaderAt, size int64, opts Options) ([]Member, error) {
	if opts.Policy != PolicyStrict {
		return nil, errors.New("archive: List supports only PolicyStrict")
	}
	if err := checkStrictOptions(opts); err != nil {
		return nil, err
	}
	placed, err := walkArchive(ra, size, nil, opts)
	if err != nil {
		return nil, err
	}
	members := make([]Member, len(placed))
	for i, p := range placed {
		members[i] = Member{Path: p.Path, Kind: p.Kind, Mode: p.Mode}
	}
	return members, nil
}

// walkArchive extracts the archive in ra by opts.Format or, when root is nil,
// lists it; the caller has validated opts. Only PolicyStrict can list.
func walkArchive(ra io.ReaderAt, size int64, root *os.Root, opts Options) ([]Placed, error) {
	switch opts.Format {
	case FormatZip:
		if opts.Policy != PolicyStrict {
			return nil, errors.New("archive: zip archives can only be extracted with PolicyStrict")
		}
		zr, err := zip.NewReader(ra, size)
		if err != nil {
			return nil, fmt.Errorf("read zip archive: %w", err)
		}
		// The central directory lists every member, so an over-long archive
		// is refused before anything is written.
		if len(zr.File) > opts.Limits.MaxEntries {
			return nil, fmt.Errorf("extraction rejected: archive exceeds %d entries (the zip lists %d members)", opts.Limits.MaxEntries, len(zr.File))
		}
		return extractStrict(zipMembers(zr), root, opts)
	case FormatTar, FormatTarGz, FormatTarZst, FormatTarXz:
		return extractTarFormat(io.NewSectionReader(ra, 0, size), root, opts)
	default:
		return nil, fmt.Errorf("archive: unsupported format %s", opts.Format)
	}
}

// extractTarFormat decompresses r as opts.Format, checks that the payload is a
// tar stream, and walks it: with the strict extractor under PolicyStrict
// (which lists instead of extracting when root is nil), else with ExtractTar.
func extractTarFormat(r io.Reader, root *os.Root, opts Options) ([]Placed, error) {
	stream, compression := r, ""
	switch opts.Format {
	case FormatTarGz:
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("read gzip stream: %w", err)
		}
		defer func() { _ = gz.Close() }()
		stream, compression = gz, "gzip"
	case FormatTarZst:
		// The library defaults allow a 512 MiB window and four concurrent
		// decoders, so a few header bytes could claim that much memory.
		dec, err := zstd.NewReader(r,
			zstd.WithDecoderMaxWindow(maxZstdWindow),
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(uint64(streamBudget(opts.Limits)))) //nolint:gosec // G115: Extract validated Limits, so streamBudget is positive
		if err != nil {
			return nil, fmt.Errorf("read zstd stream: %w", err)
		}
		defer dec.Close()
		stream, compression = dec, "zstd"
	case FormatTarXz:
		xr, err := newXZReader(r)
		if err != nil {
			return nil, fmt.Errorf("read xz stream: %w", err)
		}
		stream, compression = xr, "xz"
	}
	payload := bufio.NewReaderSize(&cappedReader{r: stream, max: streamBudget(opts.Limits)}, 64<<10)
	head, err := payload.Peek(tarBlockSize)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read %s archive: %w", opts.Format, err)
	}
	if !isTarBlock(head) {
		if compression == "" {
			return nil, errors.New("archive is not a tar archive")
		}
		return nil, fmt.Errorf("archive is %s-compressed but does not contain a tar archive", compression)
	}
	if opts.Policy == PolicyStrict {
		return extractStrict(tarMembers(payload), root, opts)
	}
	return ExtractTar(payload, root, opts)
}

// isTarBlock reports whether head is a whole tar header block: one carrying
// the ustar magic, or the all-zero end-of-archive block that opens an empty
// tar.
func isTarBlock(head []byte) bool {
	if len(head) < tarBlockSize {
		return false
	}
	if isUstar(head) {
		return true
	}
	for _, b := range head {
		if b != 0 {
			return false
		}
	}
	return true
}

// streamBudget is how many bytes a decompressed tar stream may hold:
// MaxTotalBytes of content plus framing for MaxEntries entries. lim must be
// validated (every field positive); the result is then positive, saturating
// at math.MaxInt64 instead of overflowing.
func streamBudget(lim Limits) int64 {
	framing := int64(lim.MaxEntries)
	if framing > (math.MaxInt64-lim.MaxTotalBytes)/tarEntryOverhead {
		return math.MaxInt64
	}
	return lim.MaxTotalBytes + framing*tarEntryOverhead
}

// cappedReader fails once more than max bytes have come out of r. It bounds
// decompression work as a whole, including members that are skipped rather
// than written (excluded by Include or StripComponents) and pax headers,
// which the per-member limits never see. cappedReader is what enforces the
// budget on a streamed archive. The zstd decoder's WithDecoderMaxMemory only
// bounds the window and the content size a frame declares; when it trips
// first, its size error is reported as this one, so the refusal reads the
// same in every format. A frame declaring a window above maxZstdWindow, or
// above the budget when that is smaller, fails with zstd's own window error
// instead.
type cappedReader struct {
	r    io.Reader
	read int64
	max  int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += int64(n)
	if c.read > c.max || errors.Is(err, zstd.ErrDecoderSizeExceeded) {
		return 0, fmt.Errorf("extraction rejected: the decompressed archive exceeds %d bytes", c.max)
	}
	return n, err
}
