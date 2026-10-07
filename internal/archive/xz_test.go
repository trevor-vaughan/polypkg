package archive

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"
)

// xzTestBlock is one block of a hand-built xz stream.
type xzTestBlock struct {
	dictCode byte   // the LZMA2 dictionary-size code the block header declares
	lzma2    []byte // the block's LZMA2 chunks, end marker included
	out      int    // how many bytes the chunks decode to, for the index
	header   []byte // replaces the header xzBlockHeader(dictCode) builds, if set
	pad      []byte // replaces the zero padding after the block, if set
}

// storedBlock is a block holding data in one uncompressed LZMA2 chunk.
func storedBlock(dictCode byte, data []byte) xzTestBlock {
	chunk := []byte{0x01, byte((len(data) - 1) >> 8), byte(len(data) - 1)}
	chunk = append(append(chunk, data...), 0x00)
	return xzTestBlock{dictCode: dictCode, lzma2: chunk, out: len(data)}
}

// xzBlockHeader encodes a 12-byte block header for one LZMA2 filter with
// dictionary-size code dictCode and no size fields.
func xzBlockHeader(dictCode byte) []byte {
	return xzHeaderOf(0x00, xzLZMA2Filter, 0x01, dictCode)
}

// xzHeaderOf encodes a block header with flags and the bytes that follow
// them (size fields and filter flags), zero-padded and with a valid CRC, so a
// test can declare what no encoder would.
func xzHeaderOf(flags byte, fields ...byte) []byte {
	h := append([]byte{0, flags}, fields...)
	for len(h)%4 != 0 {
		h = append(h, 0)
	}
	h[0] = byte((len(h)+4)/4 - 1)
	return binary.LittleEndian.AppendUint32(h, crc32.ChecksumIEEE(h))
}

// xzPad appends zero bytes to b until its length is a multiple of four.
func xzPad(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// xzStreamOf hand-builds a complete single-stream xz file with check type
// None, so tests can declare dictionaries no encoder would choose.
func xzStreamOf(blocks ...xzTestBlock) []byte {
	flags := []byte{0x00, 0x00}
	out := append(append([]byte{}, xzMagic...), flags...)
	out = binary.LittleEndian.AppendUint32(out, crc32.ChecksumIEEE(flags))
	index := binary.AppendUvarint([]byte{0x00}, uint64(len(blocks)))
	for _, b := range blocks {
		header := b.header
		if header == nil {
			header = xzBlockHeader(b.dictCode)
		}
		out = append(append(out, header...), b.lzma2...)
		if b.pad != nil {
			out = append(out, b.pad...)
		} else {
			out = xzPad(out)
		}
		index = binary.AppendUvarint(index, uint64(len(header)+len(b.lzma2)))
		index = binary.AppendUvarint(index, uint64(b.out))
	}
	index = xzPad(index)
	index = binary.LittleEndian.AppendUint32(index, crc32.ChecksumIEEE(index))
	out = append(out, index...)
	footer := binary.LittleEndian.AppendUint32(nil, uint32(len(index)/4-1))
	footer = append(footer, flags...)
	out = binary.LittleEndian.AppendUint32(out, crc32.ChecksumIEEE(footer))
	return append(append(out, footer...), xzFooterMagic...)
}

// readXZ decompresses all of data with xzReader.
func readXZ(data []byte) ([]byte, error) {
	x, err := newXZReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(x)
}

// encodeXZ compresses data with the ulikunitz/xz writer under cfg.
func encodeXZ(t *testing.T, cfg xz.WriterConfig, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := cfg.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestXZReaderDecodesWhatTheEncoderWrites(t *testing.T) {
	data := bytes.Repeat([]byte("polypkg xz round trip "), 4096)
	cases := map[string]xz.WriterConfig{
		"default (CRC-64)": {},
		"CRC-32":           {CheckSum: xz.CRC32},
		"SHA-256":          {CheckSum: xz.SHA256},
		"no check":         {NoCheckSum: true},
		"many blocks":      {BlockSize: 4096},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := readXZ(encodeXZ(t, cfg, data))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatal("decoded data differs from the input")
			}
		})
	}
}

// TestXZReaderDecodesXZUtilsOutput decodes files written by xz (XZ Utils)
// 5.6.2 from the output of `seq 1 5000`: presets 0 and -9e, each check type,
// small blocks (xz -T2 --block-size=4KiB), a single-threaded file whose block
// headers declare no sizes (xz -T1), and two streams joined with stream
// padding. Every file but nosizes.xz declares its blocks' sizes.
func TestXZReaderDecodesXZUtilsOutput(t *testing.T) {
	var want []byte
	for i := 1; i <= 5000; i++ {
		want = append(strconv.AppendInt(want, int64(i), 10), '\n')
	}
	for _, name := range []string{"preset0", "preset9e", "crc32", "sha256", "nocheck", "blocks", "nosizes", "concatenated"} {
		t.Run(name, func(t *testing.T) {
			file, err := os.ReadFile(filepath.Join("testdata", "xz", name+".xz"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := readXZ(file)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("decoded data differs from seq 1 5000")
			}
		})
	}
}

// TestXZReaderSizesTheDictionaryToTheBlock pins that a block whose header
// declares its uncompressed size gets a dictionary no larger than that size
// (at least 4 KiB), not the one it declares: 32 one-byte blocks that each
// declare a 64 MiB dictionary would otherwise allocate 2 GiB.
func TestXZReaderSizesTheDictionaryToTheBlock(t *testing.T) {
	blocks := make([]xzTestBlock, 0, 32)
	for range 32 {
		b := storedBlock(28, []byte("x"))
		b.header = xzHeaderOf(0x80, 1, xzLZMA2Filter, 0x01, 28)
		blocks = append(blocks, b)
	}
	file := xzStreamOf(blocks...)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got, err := readXZ(file)
	runtime.ReadMemStats(&after)
	if err != nil || string(got) != strings.Repeat("x", 32) {
		t.Fatalf("decode = %q, %v", got, err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 16<<20 {
		t.Fatalf("decoding allocated %d MiB, want under 16 MiB", alloc>>20)
	}
}

func TestXZReaderReadsConcatenatedStreamsAndPadding(t *testing.T) {
	first := encodeXZ(t, xz.WriterConfig{}, []byte("first "))
	second := encodeXZ(t, xz.WriterConfig{CheckSum: xz.CRC32}, []byte("second"))
	file := append(append(append([]byte{}, first...), make([]byte, 8)...), second...)
	file = append(file, make([]byte, 4)...)
	got, err := readXZ(file)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got) != "first second" {
		t.Fatalf("decoded %q, want %q", got, "first second")
	}
}

func TestXZReaderCapsTheDictionary(t *testing.T) {
	// Code 28 declares 64 MiB (maxXZDict), 29 declares 96 MiB and 40 the
	// format's 4 GiB maximum.
	if _, err := readXZ(xzStreamOf(storedBlock(28, []byte("at the cap")))); err != nil {
		t.Fatalf("a 64 MiB dictionary was refused: %v", err)
	}
	for _, code := range []byte{29, 40} {
		_, err := readXZ(xzStreamOf(storedBlock(code, []byte("x"))))
		if err == nil || !strings.HasPrefix(err.Error(), "xz: a block declares a ") || !strings.Contains(err.Error(), "more than the 64 MiB limit") {
			t.Fatalf("dictionary code %d: error = %v, want the dictionary refusal", code, err)
		}
	}
}

func TestXZReaderChecksEveryBlockHeader(t *testing.T) {
	file := xzStreamOf(storedBlock(0, []byte("small")), storedBlock(40, []byte("huge")))
	got, err := readXZ(file)
	if err == nil || !strings.Contains(err.Error(), "4095 MiB dictionary") {
		t.Fatalf("error = %v, want the second block's dictionary refused", err)
	}
	if string(got) != "small" {
		t.Fatalf("decoded %q before the refusal, want the first block's %q", got, "small")
	}
}

// TestXZReaderChecksTheBlockHeaderTheDecoderReaches pins why the cap cannot
// be a pre-pass over block boundaries. The first block's only LZMA chunk
// declares 64 compressed bytes, but the decoder finishes its single output
// byte after 6 of them and reads the next chunk header from inside the
// declared range. Those bytes end the block early, and a block header
// declaring a 4 GiB dictionary follows, at an offset a pre-pass trusting the
// declared size would skip.
func TestXZReaderChecksTheBlockHeaderTheDecoderReaches(t *testing.T) {
	declared := make([]byte, 64)
	// declared[0:6] is the range coder's input: all zero decodes one zero
	// byte. declared[6] = 0x00 ends the LZMA2 data, and three zero bytes pad
	// the block (6-byte chunk header + 7 bytes = 13) to 16 bytes.
	copy(declared[10:], xzBlockHeader(40))
	lzma2 := append([]byte{0xe0, 0x00, 0x00, 0x00, byte(len(declared) - 1), 0x5d}, declared...)
	lzma2 = append(lzma2, 0x00)
	_, err := readXZ(xzStreamOf(xzTestBlock{dictCode: 0, lzma2: lzma2, out: 1}))
	if err == nil || !strings.Contains(err.Error(), "4095 MiB dictionary") {
		t.Fatalf("error = %v, want the hidden block's dictionary refused", err)
	}
}

// TestXZReaderStopsAtTheDeclaredUncompressedSize pins that a block producing
// more than its header's uncompressed size yields only the declared bytes,
// with the refusal in the same Read.
func TestXZReaderStopsAtTheDeclaredUncompressedSize(t *testing.T) {
	block := storedBlock(0, []byte("abcdef"))
	block.header = xzHeaderOf(0x80, 2, xzLZMA2Filter, 0x01, 0)
	x, err := newXZReader(bytes.NewReader(xzStreamOf(block)))
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 64)
	n, err := x.Read(p)
	if string(p[:n]) != "ab" || err == nil || !strings.Contains(err.Error(), "xz: a block holds more data than its header declares") {
		t.Fatalf("Read = %q, %v; want \"ab\" and the size refusal", p[:n], err)
	}
	if n, err := x.Read(p); n != 0 || err == nil {
		t.Fatalf("Read after the refusal = %d, %v; want 0 and the refusal again", n, err)
	}
}

func TestXZReaderRefusesMalformedFiles(t *testing.T) {
	valid := encodeXZ(t, xz.WriterConfig{}, bytes.Repeat([]byte("data "), 100))
	headerStart := xzStreamHeaderLen
	mutate := func(f func(b []byte) []byte) []byte {
		return f(append([]byte{}, valid...))
	}
	cases := map[string]struct {
		file []byte
		want string
	}{
		"truncated in the header":             {valid[:8], "xz: unexpected EOF"},
		"truncated in a block":                {valid[:len(valid)/2], "unexpected EOF"},
		"truncated in the footer":             {valid[:len(valid)-3], "xz: unexpected EOF"},
		"trailing bytes that are not padding": {append(append([]byte{}, valid...), 1, 2, 3, 4), "xz: unexpected EOF"},
		"padding not a multiple of four":      {append(append([]byte{}, valid...), 0, 0), "xz: unexpected EOF"},
		"stream header checksum": {
			mutate(func(b []byte) []byte { b[8] ^= 0xff; return b }),
			"xz: stream header checksum mismatch",
		},
		"block header checksum": {
			mutate(func(b []byte) []byte { b[headerStart+1] ^= 0x01; return b }),
			"xz: block header checksum mismatch",
		},
		"block check": {mutate(func(b []byte) []byte {
			indexLen := (int(binary.LittleEndian.Uint32(b[len(b)-8:])) + 1) * 4
			b[len(b)-xzStreamHeaderLen-indexLen-1] ^= 0xff // the check's last byte
			return b
		}), "xz: block check mismatch"},
		"index record": {mutate(func(b []byte) []byte {
			indexLen := (int(binary.LittleEndian.Uint32(b[len(b)-8:])) + 1) * 4
			b[len(b)-xzStreamHeaderLen-indexLen+2] ^= 0x01 // the first record's unpadded size
			return b
		}), "xz: the index entry for block 0 does not match the block"},
		"footer magic":    {mutate(func(b []byte) []byte { b[len(b)-1] = 'X'; return b }), "xz: bad stream footer magic"},
		"footer checksum": {mutate(func(b []byte) []byte { b[len(b)-12] ^= 0xff; return b }), "xz: stream footer checksum mismatch"},
		"invalid dictionary code": {
			xzStreamOf(storedBlock(41, []byte("x"))),
			"xz: malformed block header: lzma: invalid dictionary size code",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := readXZ(tc.file)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.HasPrefix(err.Error(), "xz: ") {
				t.Fatalf("error = %v, want an \"xz: \" error containing %q", err, tc.want)
			}
		})
	}
	t.Run("an index that disagrees with the block", func(t *testing.T) {
		// A well-formed index (its CRC is right) that claims four output
		// bytes for a three-byte block.
		block := storedBlock(0, []byte("abc"))
		block.out = 4
		if _, err := readXZ(xzStreamOf(block)); err == nil || !strings.Contains(err.Error(), "xz: the index entry for block 0 does not match") {
			t.Fatalf("error = %v, want the index mismatch", err)
		}
	})
}

// TestExtractRefusesHugeXZDictionary pins the cap at the Extract boundary: a
// tar.xz whose first block declares 4 GiB is refused before any member is
// read or anything is written.
func TestExtractRefusesHugeXZDictionary(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	file := xzStreamOf(storedBlock(40, make([]byte, 1024)))
	opts := Options{Format: FormatTarXz, Policy: PolicyStrict, Limits: DefaultLimits(), DirPerm: 0o755}
	_, err = Extract(bytes.NewReader(file), int64(len(file)), root, opts)
	if err == nil || !strings.Contains(err.Error(), "dictionary, more than the 64 MiB limit") {
		t.Fatalf("error = %v, want the dictionary refusal", err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("wrote %d entries before refusing the archive", len(ents))
	}
}

// xzFixIndexCRC recomputes the index CRC of the single-stream file b, whose
// footer's backward size locates the index.
func xzFixIndexCRC(b []byte) []byte {
	indexLen := (int(binary.LittleEndian.Uint32(b[len(b)-8:])) + 1) * 4
	index := b[len(b)-xzStreamHeaderLen-indexLen : len(b)-xzStreamHeaderLen]
	binary.LittleEndian.PutUint32(index[len(index)-4:], crc32.ChecksumIEEE(index[:len(index)-4]))
	return b
}

// xzFixFooterCRC recomputes the stream footer CRC of b.
func xzFixFooterCRC(b []byte) []byte {
	foot := b[len(b)-xzStreamHeaderLen:]
	binary.LittleEndian.PutUint32(foot[:4], crc32.ChecksumIEEE(foot[4:10]))
	return b
}

// TestXZReaderRefusesMalformedStructures covers the refusals that need a
// structure no encoder writes: each file is well-formed except for the one
// field the case names, and every CRC over that field is valid.
func TestXZReaderRefusesMalformedStructures(t *testing.T) {
	abc := func(f func(b *xzTestBlock)) []byte {
		b := storedBlock(0, []byte("abc")) // 7 bytes of LZMA2 data
		f(&b)
		return xzStreamOf(b)
	}
	plain := func(f func(b []byte)) []byte {
		b := xzStreamOf(storedBlock(0, []byte("abc")))
		f(b)
		return b
	}
	cases := map[string]struct {
		file []byte
		want string
	}{
		"not an xz stream": {plain(func(b []byte) { b[0] = 0 }), "xz: not an xz stream"},
		"reserved stream flags": {plain(func(b []byte) {
			b[6] = 0x01
			binary.LittleEndian.PutUint32(b[8:], crc32.ChecksumIEEE(b[6:8]))
		}), "xz: unsupported stream flags"},
		"unknown check type": {plain(func(b []byte) {
			b[7] = 0x02
			binary.LittleEndian.PutUint32(b[8:], crc32.ChecksumIEEE(b[6:8]))
		}), "xz: unsupported check type 0x2"},
		"declared uncompressed size larger than the block": {abc(func(b *xzTestBlock) {
			b.header = xzHeaderOf(0x80, 5, xzLZMA2Filter, 0x01, 0)
		}), "xz: a block's size does not match its header"},
		"declared compressed size wrong": {abc(func(b *xzTestBlock) {
			b.header = xzHeaderOf(0x40, 8, xzLZMA2Filter, 0x01, 0)
		}), "xz: a block's size does not match its header"},
		"non-zero block padding": {abc(func(b *xzTestBlock) { b.pad = []byte{1} }), "xz: non-zero block padding"},
		"reserved block flags": {abc(func(b *xzTestBlock) {
			b.header = xzHeaderOf(0x04, xzLZMA2Filter, 0x01, 0)
		}), "xz: unsupported block flags 0x4"},
		"two filters": {abc(func(b *xzTestBlock) {
			b.header = xzHeaderOf(0x01, 0x03, 0x01, 0x00, xzLZMA2Filter, 0x01, 0)
		}), "xz: a block uses 2 filters; only a single LZMA2 filter is supported"},
		"a filter other than LZMA2": {abc(func(b *xzTestBlock) {
			b.header = xzHeaderOf(0x00, 0x03, 0x01, 0x00)
		}), "xz: unsupported filter 0x3; only LZMA2 is supported"},
		"LZMA2 properties of the wrong length": {abc(func(b *xzTestBlock) {
			b.header = xzHeaderOf(0x00, xzLZMA2Filter, 0x02, 0, 0)
		}), "xz: malformed block header: LZMA2 properties must be one byte"},
		"non-zero block header padding": {abc(func(b *xzTestBlock) {
			b.header = xzHeaderOf(0x00, xzLZMA2Filter, 0x01, 0, 0, 0, 1)
		}), "xz: non-zero block header padding"},
		"index block count": {plain(func(b []byte) {
			indexLen := (int(binary.LittleEndian.Uint32(b[len(b)-8:])) + 1) * 4
			b[len(b)-xzStreamHeaderLen-indexLen+1] = 2
			xzFixIndexCRC(b)
		}), "xz: the index lists 2 blocks; the stream holds 1"},
		"index checksum": {plain(func(b []byte) {
			b[len(b)-xzStreamHeaderLen-1] ^= 0xff
		}), "xz: index checksum mismatch"},
		"footer flags": {plain(func(b []byte) {
			b[len(b)-3] = 0x01
			xzFixFooterCRC(b)
		}), "xz: stream footer flags differ from the header's"},
		"footer index size": {plain(func(b []byte) {
			b[len(b)-8]++
			xzFixFooterCRC(b)
		}), "xz: stream footer gives the wrong index size"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := readXZ(tc.file)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// FuzzXZReader checks that the walker never panics, labels every error, and
// agrees with ulikunitz/xz's own reader on every file it accepts. The seeds
// carry no block check, so a mutation is not stopped at a check mismatch and
// reaches deeper into the container.
func FuzzXZReader(f *testing.F) {
	for _, cfg := range []xz.WriterConfig{{NoCheckSum: true}, {NoCheckSum: true, BlockSize: 64}} {
		var buf bytes.Buffer
		w, err := cfg.NewWriter(&buf)
		if err != nil {
			f.Fatal(err)
		}
		if _, err := w.Write(bytes.Repeat([]byte("fuzz xz "), 40)); err != nil {
			f.Fatal(err)
		}
		if err := w.Close(); err != nil {
			f.Fatal(err)
		}
		f.Add(buf.Bytes())
	}
	f.Add(xzStreamOf(storedBlock(0, []byte("abc")), storedBlock(0, []byte("def"))))
	f.Fuzz(func(t *testing.T, data []byte) {
		const limit = 16 << 20
		x, err := newXZReader(bytes.NewReader(data))
		if err != nil {
			if !strings.HasPrefix(err.Error(), "xz: ") {
				t.Fatalf("unlabelled error %q", err)
			}
			return
		}
		got, err := io.ReadAll(io.LimitReader(x, limit))
		if err != nil {
			if !strings.HasPrefix(err.Error(), "xz: ") {
				t.Fatalf("unlabelled error %q", err)
			}
			return
		}
		if len(got) == limit {
			return
		}
		ref, err := xz.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("accepted a file xz.NewReader refuses: %v", err)
		}
		want, err := io.ReadAll(ref)
		if err != nil {
			t.Fatalf("accepted a file xz.Reader refuses: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("decoded output differs from xz.Reader's")
		}
	})
}
