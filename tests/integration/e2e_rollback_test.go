package integration

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/audit"
	"github.com/trevor-vaughan/polypkg/internal/runner"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// errInjectedCommit is the sentinel CommitGeneration failure used to drive
// runner abort tests.
var errInjectedCommit = errors.New("injected commit failure")

// failingSubstrate fails its CommitGeneration to test rollback.
type failingSubstrate struct {
	*substrate.OwnStore
}

func (f *failingSubstrate) CommitGeneration(txID string, m *schema.Manifest, own *schema.Ownership, configBases map[string][]byte) (int, error) {
	return 0, errInjectedCommit
}

var _ = Describe("rollback", func() {
	It("aborts the apply and records the failure when CommitGeneration fails", func() {
		t := GinkgoTB()
		dir := t.TempDir()
		base, err := substrate.NewOwnStore(dir)
		Expect(err).NotTo(HaveOccurred())
		sub := &failingSubstrate{OwnStore: base}

		w, err := audit.NewFileWriter(filepath.Join(dir, "audit.log"))
		Expect(err).NotTo(HaveOccurred())
		defer w.Close()

		r := runner.New(runner.Options{
			Substrate: sub, AuditWriter: w, Scope: "user",
			LockPath: filepath.Join(dir, "apply.lock"),
		})
		_, err = r.Run(context.Background(), &schema.Manifest{
			Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{},
		}, nil)
		Expect(err).To(HaveOccurred())

		// Confirm active symlink does not exist (apply was aborted).
		_, err = os.Readlink(filepath.Join(dir, "active"))
		Expect(err).To(HaveOccurred())

		// Confirm audit log contains the failure.
		auditBytes, err := os.ReadFile(filepath.Join(dir, "audit.log"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(auditBytes)).To(ContainSubstring("apply.failed"))
	})
})
