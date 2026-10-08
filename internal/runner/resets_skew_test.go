package runner

import (
	"errors"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("loadResets version skew", func() {
	It("names pending-resets.json when a newer polypkg wrote it", func() {
		p := filepath.Join(GinkgoT().TempDir(), "pending-resets.json")
		Expect(os.WriteFile(p, []byte(`{"schema":"polypkg.resets/v2","scope":"user","paths":[]}`), 0o600)).To(Succeed())

		_, _, err := New(Options{Scope: "user", ResetsPath: p}).loadResets()

		var ne *schema.NewerSchemaError
		Expect(errors.As(err, &ne)).To(BeTrue(), "got %v", err)
		Expect(ne.Path).To(Equal(p))
	})
})
