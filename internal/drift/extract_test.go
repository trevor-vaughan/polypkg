package drift

import (
	"os"
	"path/filepath"

	ginkgo "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = ginkgo.Describe("Inspect (extract action)", func() {
	const body = "#!/bin/sh\necho app\n"

	// extractTree places an extracted directory, file and symlink and returns
	// the active root with the ownership an apply would have recorded for them.
	extractTree := func() (string, *schema.Ownership) {
		t := ginkgo.GinkgoTB()
		root := setupTree(t,
			fsEntry{Path: "hello/dist/bin", Type: "dir", Mode: 0o700},
			fsEntry{Path: "hello/dist/bin/app", Type: "file", Mode: 0o755, Content: []byte(body)},
			fsEntry{Path: "hello/dist/bin/app-link", Type: "symlink", Target: "app"},
		)
		app := filepath.Join(root, "hello/dist/bin/app")
		// os.WriteFile honours the umask; pin the mode the entry records.
		Expect(os.Chmod(app, 0o755)).To(Succeed())
		return root, &schema.Ownership{Entries: []schema.OwnershipEntry{
			{Path: "hello/dist/bin", Action: "extract",
				Expected: schema.Expected{FileType: "dir", Mode: "0700"}},
			{Path: "hello/dist/bin/app", Action: "extract",
				Expected: schema.Expected{FileType: "regular", ContentHash: blake3Hex([]byte(body)), Mode: "0755"},
				Stat:     statOf(t, app)},
			{Path: "hello/dist/bin/app-link", Action: "extract",
				Expected: schema.Expected{FileType: "symlink", Target: "app"}},
		}}
	}

	expectOne := func(got []Entry, path string, reason Reason, observed string) {
		Expect(got).To(HaveLen(1))
		Expect(got[0].Owned.Path).To(Equal(path))
		Expect(got[0].Reason).To(Equal(reason))
		Expect(got[0].Observed).To(Equal(observed))
	}

	ginkgo.It("reports no drift for an untouched extracted tree", func() {
		root, own := extractTree()
		got, err := Inspect(own, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeEmpty())
	})

	ginkgo.It("reports ReasonContent when an extracted file's content changes", func() {
		root, own := extractTree()
		Expect(os.WriteFile(filepath.Join(root, "hello/dist/bin/app"), []byte("tampered\n"), 0o755)).To(Succeed())
		got, err := Inspect(own, root)
		Expect(err).NotTo(HaveOccurred())
		expectOne(got, "hello/dist/bin/app", ReasonContent, blake3Hex([]byte("tampered\n")))
	})

	ginkgo.It("reports ReasonMode when an extracted file's mode changes", func() {
		root, own := extractTree()
		Expect(os.Chmod(filepath.Join(root, "hello/dist/bin/app"), 0o700)).To(Succeed())
		got, err := Inspect(own, root)
		Expect(err).NotTo(HaveOccurred())
		expectOne(got, "hello/dist/bin/app", ReasonMode, "0700")
	})

	ginkgo.It("reports ReasonFileType when an extracted file is replaced by a symlink", func() {
		root, own := extractTree()
		app := filepath.Join(root, "hello/dist/bin/app")
		Expect(os.Remove(app)).To(Succeed())
		Expect(os.Symlink("/etc/hostname", app)).To(Succeed())
		got, err := Inspect(own, root)
		Expect(err).NotTo(HaveOccurred())
		expectOne(got, "hello/dist/bin/app", ReasonFileType, "symlink")
	})

	ginkgo.It("reports ReasonMissing when an extracted file is deleted", func() {
		root, own := extractTree()
		Expect(os.Remove(filepath.Join(root, "hello/dist/bin/app"))).To(Succeed())
		got, err := Inspect(own, root)
		Expect(err).NotTo(HaveOccurred())
		expectOne(got, "hello/dist/bin/app", ReasonMissing, "absent")
	})

	ginkgo.It("reports ReasonTarget when an extracted symlink is repointed", func() {
		root, own := extractTree()
		link := filepath.Join(root, "hello/dist/bin/app-link")
		Expect(os.Remove(link)).To(Succeed())
		Expect(os.Symlink("other", link)).To(Succeed())
		got, err := Inspect(own, root)
		Expect(err).NotTo(HaveOccurred())
		expectOne(got, "hello/dist/bin/app-link", ReasonTarget, "other")
	})

	ginkgo.It("reports ReasonMode when an extracted directory's mode changes", func() {
		root, own := extractTree()
		Expect(os.Chmod(filepath.Join(root, "hello/dist/bin"), 0o755)).To(Succeed())
		got, err := Inspect(own, root)
		Expect(err).NotTo(HaveOccurred())
		expectOne(got, "hello/dist/bin", ReasonMode, "0755")
	})
})
