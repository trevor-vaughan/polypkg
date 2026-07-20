package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("FileWriter", func() {
	It("writes events as JSON lines with all fields preserved", func() {
		dir := GinkgoT().TempDir()
		logPath := filepath.Join(dir, "audit.log")
		w, err := NewFileWriter(logPath)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = w.Close() })

		Expect(w.Write(Event{
			Schema: "polypkg.audit/v1",
			Scope:  "user",
			TxID:   "tx-1",
			Event:  "apply.start",
			Fields: map[string]any{"manifest_hash": "sha256:abc"},
		})).To(Succeed())

		Expect(w.Close()).To(Succeed())

		data, err := os.ReadFile(logPath)
		Expect(err).NotTo(HaveOccurred())
		scanner := bufio.NewScanner(bytes.NewReader(data))
		Expect(scanner.Scan()).To(BeTrue())
		var line map[string]any
		Expect(json.Unmarshal(scanner.Bytes(), &line)).To(Succeed())
		Expect(line["schema"]).To(Equal("polypkg.audit/v1"))
		Expect(line["scope"]).To(Equal("user"))
		Expect(line["tx_id"]).To(Equal("tx-1"))
		Expect(line["event"]).To(Equal("apply.start"))
		Expect(line["manifest_hash"]).To(Equal("sha256:abc"))
	})
})
