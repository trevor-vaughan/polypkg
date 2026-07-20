package schema

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Ownership Expected.Master", func() {
	It("parses and round-trips a follower entry's master field", func() {
		doc := `{
		  "schema": "polypkg.ownership/v1",
		  "scope": "user",
		  "entries": [{
		    "path": "man/man1/editor.1",
		    "package": "vim",
		    "version": "1.0.0",
		    "action": "alternatives",
		    "expected": {"file_type": "symlink", "target": "/a/vim/share/man/man1/vim.1", "master": "editor"},
		    "drift_policy": "notify_heal",
		    "stat": {"size": 0, "mtime_ns": 0, "inode": 0}
		  }]
		}`
		own, err := ParseOwnership(strings.NewReader(doc))
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Expected.Master).To(Equal("editor"))
	})
})
