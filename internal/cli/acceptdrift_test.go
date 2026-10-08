package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"lukechampine.com/blake3"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("writeAcceptedDrift", func() {
	It("captures live state for a known managed path", func() {
		tmp := GinkgoT().TempDir()
		active := filepath.Join(tmp, "active")
		Expect(os.MkdirAll(filepath.Join(active, "hello/bin"), 0o755)).To(Succeed())
		Expect(os.Chmod(filepath.Join(active, "hello/bin"), 0o700)).To(Succeed()) // drifted from 0755

		prior := &schema.Ownership{
			Schema: "polypkg.ownership/v1", Scope: "user",
			Entries: []schema.OwnershipEntry{{
				Path: "hello/bin", Package: "hello", Version: "1.0.0", Action: "dir",
				Expected:    schema.Expected{FileType: "dir", Mode: "0755"},
				DriftPolicy: "refuse",
			}},
		}

		outPath := filepath.Join(tmp, "accepted-drift.json")
		Expect(writeAcceptedDrift(outPath, 7, active, prior, []string{"hello/bin"})).To(Succeed())

		data, err := os.ReadFile(filepath.Clean(outPath))
		Expect(err).NotTo(HaveOccurred())
		var got schema.AcceptedDrift
		Expect(json.Unmarshal(data, &got)).To(Succeed())
		Expect(got.Schema).To(Equal("polypkg.accepted-drift/v1"))
		Expect(got.Generation).To(Equal(7))
		Expect(got.Paths).To(HaveKey("hello/bin"))
		Expect(got.Paths["hello/bin"].Expected.Mode).To(Equal("0700"))
		Expect(got.Paths["hello/bin"].Expected.FileType).To(Equal("dir"))
	})

	It("rejects a path that is not in the prior ownership index", func() {
		tmp := GinkgoT().TempDir()
		active := filepath.Join(tmp, "active")
		Expect(os.MkdirAll(active, 0o755)).To(Succeed())
		prior := &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}
		err := writeAcceptedDrift(filepath.Join(tmp, "out.json"), 1, active, prior, []string{"nope"})
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError")
		Expect(cliErr.Msg).To(ContainSubstring("not a managed path"))
		Expect(cliErr.Hint).To(ContainSubstring("status -vv"))
	})

	It("merges with an existing record for the same generation", func() {
		tmp := GinkgoT().TempDir()
		active := filepath.Join(tmp, "active")
		Expect(os.MkdirAll(filepath.Join(active, "hello/bin"), 0o755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(active, "hello/share"), 0o700)).To(Succeed())

		prior := &schema.Ownership{Entries: []schema.OwnershipEntry{
			{Path: "hello/bin", Action: "dir", Expected: schema.Expected{FileType: "dir", Mode: "0755"}},
			{Path: "hello/share", Action: "dir", Expected: schema.Expected{FileType: "dir", Mode: "0755"}},
		}}

		outPath := filepath.Join(tmp, "accepted-drift.json")
		Expect(writeAcceptedDrift(outPath, 5, active, prior, []string{"hello/bin"})).To(Succeed())
		Expect(writeAcceptedDrift(outPath, 5, active, prior, []string{"hello/share"})).To(Succeed())

		data, err := os.ReadFile(filepath.Clean(outPath))
		Expect(err).NotTo(HaveOccurred())
		var got schema.AcceptedDrift
		Expect(json.Unmarshal(data, &got)).To(Succeed())
		Expect(got.Generation).To(Equal(5))
		Expect(got.Paths).To(HaveKey("hello/bin"))
		Expect(got.Paths).To(HaveKey("hello/share"))
	})

	It("captures the live content hash for a regular file an extract placed", func() {
		tmp := GinkgoT().TempDir()
		active := filepath.Join(tmp, "active")
		file := filepath.Join(active, "hello/dist/bin/app")
		Expect(os.MkdirAll(filepath.Dir(file), 0o755)).To(Succeed())
		Expect(os.WriteFile(file, []byte("tampered\n"), 0o755)).To(Succeed())
		prior := &schema.Ownership{
			Schema: "polypkg.ownership/v1", Scope: "user",
			Entries: []schema.OwnershipEntry{{
				Path: "hello/dist/bin/app", Package: "hello", Version: "1.0.0", Action: "extract",
				Expected:    schema.Expected{FileType: "regular", ContentHash: "blake3:00", Mode: "0755"},
				DriftPolicy: "refuse",
			}},
		}

		outPath := filepath.Join(tmp, "accepted-drift.json")
		Expect(writeAcceptedDrift(outPath, 3, active, prior, []string{"hello/dist/bin/app"})).To(Succeed())

		data, err := os.ReadFile(filepath.Clean(outPath))
		Expect(err).NotTo(HaveOccurred())
		var got schema.AcceptedDrift
		Expect(json.Unmarshal(data, &got)).To(Succeed())
		h := blake3.New(32, nil)
		_, _ = h.Write([]byte("tampered\n"))
		Expect(got.Paths["hello/dist/bin/app"].Expected.ContentHash).To(Equal("blake3:" + hex.EncodeToString(h.Sum(nil))))
		Expect(got.Paths["hello/dist/bin/app"].Expected.FileType).To(Equal("regular"))
	})

	It("captures no content hash for a directory an extract placed", func() {
		tmp := GinkgoT().TempDir()
		active := filepath.Join(tmp, "active")
		Expect(os.MkdirAll(filepath.Join(active, "hello/dist"), 0o755)).To(Succeed())
		prior := &schema.Ownership{
			Schema: "polypkg.ownership/v1", Scope: "user",
			Entries: []schema.OwnershipEntry{{
				Path: "hello/dist", Package: "hello", Version: "1.0.0", Action: "extract",
				Expected: schema.Expected{FileType: "dir", Mode: "0700"}, DriftPolicy: "refuse",
			}},
		}

		outPath := filepath.Join(tmp, "accepted-drift.json")
		Expect(writeAcceptedDrift(outPath, 3, active, prior, []string{"hello/dist"})).To(Succeed())

		data, err := os.ReadFile(filepath.Clean(outPath))
		Expect(err).NotTo(HaveOccurred())
		var got schema.AcceptedDrift
		Expect(json.Unmarshal(data, &got)).To(Succeed())
		Expect(got.Paths["hello/dist"].Expected.ContentHash).To(BeEmpty())
		Expect(got.Paths["hello/dist"].Expected.FileType).To(Equal("dir"))
	})
})

var _ = Describe("accept-drift command", func() {
	It("is registered on the root command", func() {
		root := NewRootCmd()
		out := &bytes.Buffer{}
		root.SetOut(out)
		root.SetErr(out)
		root.SetArgs([]string{"accept-drift", "--help"})
		Expect(root.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("accept-drift"))
	})
})
