package archive

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"math"
	"slices"

	"github.com/ulikunitz/xz/lzma"
)

// maxXZDict caps the LZMA2 dictionary an xz block may declare. The decoder
// allocates the whole declared dictionary before it reads any data, and the
// format allows up to 4 GiB, so without a cap a 100-byte file could claim
// that much memory. xz -9 and xz -e use 64 MiB.
const maxXZDict = 64 << 20

// Fields of the xz container format (tukaani.org/xz/xz-file-format.txt).
const (
	xzStreamHeaderLen = 12
	xzLZMA2Filter     = 0x21
)

var (
	xzFooterMagic = []byte{'Y', 'Z'}
	xzCRC64Table  = crc64.MakeTable(crc64.ECMA)
)

// xzReader decompresses an xz file: one or more streams, each a header, a
// run of blocks, an index and a footer, with optional zero padding after a
// stream. It walks the container itself and hands each block's LZMA2 data to
// lzma.Reader2, so it reads every block header the decoder relies on and
// refuses a dictionary over maxXZDict before the decoder allocates it.
//
// xz.Reader has no such cap (its ReaderConfig.DictCap is a floor, not a
// ceiling), and a pre-pass over the file cannot stand in for one: the LZMA
// decoder can stop short of an LZMA2 chunk's declared compressed size and
// read the next chunk header from inside it, so the decoder can reach a block
// header that a pre-pass never saw. xzReader makes every check xz.Reader
// makes: the header, block-header and index CRCs, the block check, the sizes
// a block header declares, zero padding, and the index against the blocks
// actually read.
type xzReader struct {
	src *xzSource

	// The current stream.
	inStream bool
	flags    [2]byte          // stream flags, repeated in the footer
	newCheck func() hash.Hash // nil for check type None
	checkLE  bool             // the check is a CRC, which xz stores little-endian
	checkLen int
	records  []xzRecord // one per block of the stream read so far

	// The current block; block is nil between blocks.
	block            io.Reader
	sum              hash.Hash // the block check over its output; nil for None
	headerLen        int64
	dataStart        int64 // offset of the block's first compressed byte
	out              int64 // bytes the block has produced so far
	declaredPacked   int64 // compressed size the block header declares; -1 if absent
	declaredUnpacked int64 // uncompressed size the block header declares; -1 if absent

	err error // sticky; io.EOF once the whole file has been read
}

// xzRecord is one block as the stream index lists it.
type xzRecord struct{ unpadded, uncompressed int64 }

// xzSource is the compressed file, counted so the reader knows each block's
// compressed size.
type xzSource struct {
	r *bufio.Reader
	n int64
}

func (s *xzSource) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	s.n += int64(n)
	return n, err
}

func (s *xzSource) ReadByte() (byte, error) {
	b, err := s.r.ReadByte()
	if err == nil {
		s.n++
	}
	return b, err
}

// xzIndexReader reads a stream index through src, adding every byte to the
// index CRC.
type xzIndexReader struct {
	src *xzSource
	crc hash.Hash32
}

func (r *xzIndexReader) ReadByte() (byte, error) {
	b, err := r.src.ReadByte()
	if err == nil {
		_, _ = r.crc.Write([]byte{b})
	}
	return b, err
}

// newXZReader reads the first stream header of the xz file r.
func newXZReader(r io.Reader) (*xzReader, error) {
	x := &xzReader{src: &xzSource{r: bufio.NewReaderSize(r, 64<<10)}}
	var head [xzStreamHeaderLen]byte
	if _, err := io.ReadFull(x.src, head[:]); err != nil {
		return nil, xzUnexpected(err)
	}
	if err := x.startStream(head); err != nil {
		return nil, err
	}
	return x, nil
}

// Read returns the decompressed data. It reports a malformed file, or a block
// whose dictionary exceeds maxXZDict, as an error once the data before it has
// been returned. Output past a block's declared uncompressed size is never
// returned: the Read that reaches it returns the bytes up to that size with
// the error.
func (x *xzReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, x.err
	}
	for x.err == nil {
		if x.block == nil {
			x.err = x.next()
			continue
		}
		n, err := x.block.Read(p)
		if x.declaredUnpacked >= 0 && x.out+int64(n) > x.declaredUnpacked {
			// Return only the bytes the header declared, and the refusal
			// with them, so no caller sees output the block may not hold.
			n = int(x.declaredUnpacked - x.out)
			x.out += int64(n)
			x.err = errors.New("xz: a block holds more data than its header declares")
			return n, x.err
		}
		x.out += int64(n)
		switch {
		case errors.Is(err, io.EOF):
			x.err = x.endBlock()
		case err != nil:
			x.err = fmt.Errorf("xz: %w", err)
		}
		if n > 0 {
			return n, nil
		}
	}
	return 0, x.err
}

// next reads what follows the previous block or stream: a block header, the
// index that closes the stream, or, between streams, padding and the next
// stream header. It returns io.EOF at the end of the file.
func (x *xzReader) next() error {
	if !x.inStream {
		return x.nextStream()
	}
	size, err := x.src.ReadByte()
	if err != nil {
		return xzUnexpected(err)
	}
	if size == 0 {
		return x.endStream()
	}
	return x.startBlock(size)
}

// nextStream skips stream padding (zero bytes in groups of four) and starts
// the next stream, or returns io.EOF at the end of the file.
func (x *xzReader) nextStream() error {
	var head [xzStreamHeaderLen]byte
	for {
		n, err := io.ReadFull(x.src, head[:4])
		if n == 0 && errors.Is(err, io.EOF) {
			return io.EOF
		}
		if err != nil {
			return xzUnexpected(err)
		}
		if head[0]|head[1]|head[2]|head[3] != 0 {
			break
		}
	}
	if _, err := io.ReadFull(x.src, head[4:]); err != nil {
		return xzUnexpected(err)
	}
	return x.startStream(head)
}

// startStream checks a stream header and selects the stream's block check.
func (x *xzReader) startStream(head [xzStreamHeaderLen]byte) error {
	if !bytes.Equal(head[:len(xzMagic)], xzMagic) {
		return errors.New("xz: not an xz stream")
	}
	if crc32.ChecksumIEEE(head[6:8]) != binary.LittleEndian.Uint32(head[8:]) {
		return errors.New("xz: stream header checksum mismatch")
	}
	if head[6] != 0 {
		return fmt.Errorf("xz: unsupported stream flags %#x", head[6:8])
	}
	switch head[7] {
	case 0x00:
		x.newCheck, x.checkLE, x.checkLen = nil, false, 0
	case 0x01:
		x.newCheck, x.checkLE, x.checkLen = func() hash.Hash { return crc32.NewIEEE() }, true, crc32.Size
	case 0x04:
		x.newCheck, x.checkLE, x.checkLen = func() hash.Hash { return crc64.New(xzCRC64Table) }, true, crc64.Size
	case 0x0a:
		x.newCheck, x.checkLE, x.checkLen = sha256.New, false, sha256.Size
	default:
		return fmt.Errorf("xz: unsupported check type %#x", head[7])
	}
	x.flags = [2]byte{head[6], head[7]}
	x.records = x.records[:0]
	x.inStream = true
	return nil
}

// startBlock reads the rest of a block header whose first byte is size,
// refuses a dictionary over maxXZDict, and only then starts the decoder.
func (x *xzReader) startBlock(size byte) error {
	hdr := make([]byte, (int(size)+1)*4)
	hdr[0] = size
	if _, err := io.ReadFull(x.src, hdr[1:]); err != nil {
		return xzUnexpected(err)
	}
	body := hdr[:len(hdr)-crc32.Size]
	if crc32.ChecksumIEEE(body) != binary.LittleEndian.Uint32(hdr[len(body):]) {
		return errors.New("xz: block header checksum mismatch")
	}
	flags := body[1]
	switch {
	case flags&0x3c != 0:
		return fmt.Errorf("xz: unsupported block flags %#x", flags)
	case flags&0x03 != 0:
		return fmt.Errorf("xz: a block uses %d filters; only a single LZMA2 filter is supported", flags&0x03+1)
	}
	fields := bytes.NewReader(body[2:])
	x.declaredPacked, x.declaredUnpacked = -1, -1
	var err error
	if flags&0x40 != 0 {
		if x.declaredPacked, err = xzVarint(fields); err != nil {
			return fmt.Errorf("xz: malformed block header: %w", err)
		}
	}
	if flags&0x80 != 0 {
		if x.declaredUnpacked, err = xzVarint(fields); err != nil {
			return fmt.Errorf("xz: malformed block header: %w", err)
		}
	}
	id, err := binary.ReadUvarint(fields)
	if err != nil {
		return fmt.Errorf("xz: malformed block header: %w", err)
	}
	if id != xzLZMA2Filter {
		return fmt.Errorf("xz: unsupported filter %#x; only LZMA2 is supported", id)
	}
	if n, err := binary.ReadUvarint(fields); err != nil || n != 1 {
		return errors.New("xz: malformed block header: LZMA2 properties must be one byte")
	}
	code, err := fields.ReadByte()
	if err != nil {
		return fmt.Errorf("xz: malformed block header: %w", err)
	}
	dict, err := lzma.DecodeDictCap(code)
	if err != nil {
		return fmt.Errorf("xz: malformed block header: %w", err)
	}
	if dict > maxXZDict {
		return fmt.Errorf("xz: a block declares a %d MiB dictionary, more than the %d MiB limit",
			dict>>20, maxXZDict>>20)
	}
	if bytes.Count(body[len(body)-fields.Len():], []byte{0}) != fields.Len() {
		return errors.New("xz: non-zero block header padding")
	}
	x.headerLen = int64(len(hdr))
	x.dataStart = x.src.n
	x.out = 0
	// Every block starts with a dictionary reset, so the decoder never looks
	// back further than the block's own output, which Read holds to the
	// declared uncompressed size. A block that declares that size gets a
	// dictionary of that size (lzma's 4 KiB minimum at least), so many small
	// blocks each declaring a large dictionary stay cheap. A block that
	// declares no size (xz -T1 output, for one) still allocates the
	// dictionary it declares, up to maxXZDict.
	dictCap := dict
	if x.declaredUnpacked >= 0 {
		dictCap = min(dict, max(lzma.MinDictCap, x.declaredUnpacked))
	}
	r2, err := lzma.Reader2Config{DictCap: int(dictCap)}.NewReader2(x.src)
	if err != nil {
		return fmt.Errorf("xz: start the LZMA2 decoder: %w", err)
	}
	x.block = r2
	x.sum = nil
	if x.newCheck != nil {
		x.sum = x.newCheck()
		x.block = io.TeeReader(r2, x.sum)
	}
	return nil
}

// endBlock checks what follows a block's LZMA2 data once the decoder has
// reached its end marker: the sizes the header declared, the zero padding to a
// multiple of four bytes, and the check over the block's output.
func (x *xzReader) endBlock() error {
	packed := x.src.n - x.dataStart
	if x.declaredPacked >= 0 && packed != x.declaredPacked || x.declaredUnpacked >= 0 && x.out != x.declaredUnpacked {
		return errors.New("xz: a block's size does not match its header")
	}
	padLen := int((4 - packed%4) % 4)
	tail := make([]byte, padLen+x.checkLen)
	if _, err := io.ReadFull(x.src, tail); err != nil {
		return xzUnexpected(err)
	}
	if bytes.Count(tail[:padLen], []byte{0}) != padLen {
		return errors.New("xz: non-zero block padding")
	}
	if x.sum != nil {
		want := x.sum.Sum(nil)
		if x.checkLE {
			slices.Reverse(want)
		}
		if !bytes.Equal(tail[padLen:], want) {
			return errors.New("xz: block check mismatch")
		}
	}
	x.records = append(x.records, xzRecord{unpadded: x.headerLen + packed + int64(x.checkLen), uncompressed: x.out})
	x.block, x.sum = nil, nil
	return nil
}

// endStream reads the index (its indicator byte already read) and the footer
// that close a stream, and checks them against the blocks read.
func (x *xzReader) endStream() error {
	start := x.src.n - 1
	idx := &xzIndexReader{src: x.src, crc: crc32.NewIEEE()}
	_, _ = idx.crc.Write([]byte{0})
	count, err := xzVarint(idx)
	if err != nil {
		return fmt.Errorf("xz: malformed index: %w", err)
	}
	if count != int64(len(x.records)) {
		return fmt.Errorf("xz: the index lists %d blocks; the stream holds %d", count, len(x.records))
	}
	for i, rec := range x.records {
		unpadded, err := xzVarint(idx)
		if err != nil {
			return fmt.Errorf("xz: malformed index: %w", err)
		}
		uncompressed, err := xzVarint(idx)
		if err != nil {
			return fmt.Errorf("xz: malformed index: %w", err)
		}
		if unpadded != rec.unpadded || uncompressed != rec.uncompressed {
			return fmt.Errorf("xz: the index entry for block %d does not match the block", i)
		}
	}
	for (x.src.n-start)%4 != 0 {
		b, err := idx.ReadByte()
		if err != nil {
			return xzUnexpected(err)
		}
		if b != 0 {
			return errors.New("xz: non-zero index padding")
		}
	}
	var tail [4 + xzStreamHeaderLen]byte
	if _, err := io.ReadFull(x.src, tail[:]); err != nil {
		return xzUnexpected(err)
	}
	if idx.crc.Sum32() != binary.LittleEndian.Uint32(tail[:4]) {
		return errors.New("xz: index checksum mismatch")
	}
	indexLen := x.src.n - start - xzStreamHeaderLen
	foot := tail[4:]
	switch {
	case crc32.ChecksumIEEE(foot[4:10]) != binary.LittleEndian.Uint32(foot[:4]):
		return errors.New("xz: stream footer checksum mismatch")
	case !bytes.Equal(foot[10:], xzFooterMagic):
		return errors.New("xz: bad stream footer magic")
	case !bytes.Equal(foot[8:10], x.flags[:]):
		return errors.New("xz: stream footer flags differ from the header's")
	case (int64(binary.LittleEndian.Uint32(foot[4:8]))+1)*4 != indexLen:
		return errors.New("xz: stream footer gives the wrong index size")
	}
	x.inStream = false
	return nil
}

// xzVarint reads one of the format's variable-length integers, which must
// fit an int64. Its errors carry no "xz:" prefix; callers name the structure
// the integer belongs to.
func xzVarint(r io.ByteReader) (int64, error) {
	v, err := binary.ReadUvarint(r)
	if errors.Is(err, io.EOF) {
		return 0, io.ErrUnexpectedEOF
	}
	if err != nil {
		return 0, err
	}
	if v > math.MaxInt64 {
		return 0, errors.New("integer field overflows")
	}
	return int64(v), nil
}

// xzUnexpected reports a failed read of the compressed file, turning the
// io.EOF of a read that needed more bytes into io.ErrUnexpectedEOF: the file
// ended inside a structure.
func xzUnexpected(err error) error {
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return fmt.Errorf("xz: %w", err)
}
