package source

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/archive"
)

// makeTarZst builds a tar.zst from regular files (name -> body) for the
// resource-limit specs. Failures here are framework bugs, not test failures —
// Gomega assertions abort the spec immediately.
func makeTarZst(files map[string][]byte) []byte {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for name, body := range files {
		Expect(tw.WriteHeader(&tar.Header{
			Name: name, Size: int64(len(body)), Mode: 0o644, Typeflag: tar.TypeReg,
		})).To(Succeed())
		_, err := tw.Write(body)
		Expect(err).NotTo(HaveOccurred())
	}
	Expect(tw.Close()).To(Succeed())
	var z bytes.Buffer
	enc, err := zstd.NewWriter(&z)
	Expect(err).NotTo(HaveOccurred())
	_, err = enc.Write(raw.Bytes())
	Expect(err).NotTo(HaveOccurred())
	Expect(enc.Close()).To(Succeed())
	return z.Bytes()
}

var _ = Describe("ExtractTarZst", func() {
	It("extracts every regular file with byte-identical contents", func() {
		var raw bytes.Buffer
		tw := tar.NewWriter(&raw)
		files := map[string]string{
			"polypkg.yaml":   "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n",
			"content/bin/hi": "#!/bin/sh\necho hi\n",
		}
		for name, content := range files {
			Expect(tw.WriteHeader(&tar.Header{
				Name: name, Size: int64(len(content)), Mode: 0o644,
			})).To(Succeed())
			_, err := io.WriteString(tw, content)
			Expect(err).NotTo(HaveOccurred())
		}
		Expect(tw.Close()).To(Succeed())

		var zstd_ bytes.Buffer
		enc, err := zstd.NewWriter(&zstd_)
		Expect(err).NotTo(HaveOccurred())
		_, err = enc.Write(raw.Bytes())
		Expect(err).NotTo(HaveOccurred())
		Expect(enc.Close()).To(Succeed())

		dir := GinkgoT().TempDir()
		Expect(ExtractTarZst(bytes.NewReader(zstd_.Bytes()), dir)).To(Succeed())

		for name, content := range files {
			got, err := os.ReadFile(filepath.Join(dir, name))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(got)).To(Equal(content))
		}
	})

	It("rejects a file larger than the per-file limit", func() {
		data := makeTarZst(map[string][]byte{"big": make([]byte, 20)})
		lim := archive.Limits{MaxFileBytes: 10, MaxTotalBytes: 1000, MaxEntries: 100}
		err := extractTarZst(bytes.NewReader(data), GinkgoT().TempDir(), lim)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("exceeds limit"))
	})

	It("rejects archives whose total decompressed size exceeds the cap", func() {
		// Two files, each under the per-file cap, together over the total cap.
		data := makeTarZst(map[string][]byte{
			"a": make([]byte, 8),
			"b": make([]byte, 8),
		})
		lim := archive.Limits{MaxFileBytes: 10, MaxTotalBytes: 12, MaxEntries: 100}
		err := extractTarZst(bytes.NewReader(data), GinkgoT().TempDir(), lim)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("total size"))
	})

	It("rejects archives with more entries than the cap allows", func() {
		data := makeTarZst(map[string][]byte{
			"a": {1}, "b": {1}, "c": {1}, "d": {1},
		})
		lim := archive.Limits{MaxFileBytes: 100, MaxTotalBytes: 1000, MaxEntries: 3}
		err := extractTarZst(bytes.NewReader(data), GinkgoT().TempDir(), lim)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("entries"))
	})

	It("rejects a path-traversal entry name", func() {
		var raw bytes.Buffer
		tw := tar.NewWriter(&raw)
		Expect(tw.WriteHeader(&tar.Header{
			Name: "../escape", Size: 1, Mode: 0o644,
		})).To(Succeed())
		_, err := io.WriteString(tw, "x")
		Expect(err).NotTo(HaveOccurred())
		Expect(tw.Close()).To(Succeed())

		var zstd_ bytes.Buffer
		enc, err := zstd.NewWriter(&zstd_)
		Expect(err).NotTo(HaveOccurred())
		_, err = enc.Write(raw.Bytes())
		Expect(err).NotTo(HaveOccurred())
		Expect(enc.Close()).To(Succeed())

		dir := GinkgoT().TempDir()
		err = ExtractTarZst(bytes.NewReader(zstd_.Bytes()), dir)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("traversal"))
	})

	It("rejects a symlink whose target escapes the tree", func() {
		var raw bytes.Buffer
		tw := tar.NewWriter(&raw)
		Expect(tw.WriteHeader(&tar.Header{
			Name:     "evil",
			Typeflag: tar.TypeSymlink,
			Linkname: "../../../../etc",
			Mode:     0o777,
		})).To(Succeed())
		Expect(tw.Close()).To(Succeed())

		var z bytes.Buffer
		enc, err := zstd.NewWriter(&z)
		Expect(err).NotTo(HaveOccurred())
		_, err = enc.Write(raw.Bytes())
		Expect(err).NotTo(HaveOccurred())
		Expect(enc.Close()).To(Succeed())

		dir := GinkgoT().TempDir()
		err = ExtractTarZst(bytes.NewReader(z.Bytes()), dir)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("escapes the extraction root"))
	})
})
