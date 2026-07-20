package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/cli"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("apply", func() {
	It("applies an empty profile, increments generation, and rolls back", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		profile := filepath.Join("..", "fixtures", "profiles", "empty.yaml")

		// Apply
		apply := cli.NewRootCmd()
		var out bytes.Buffer
		apply.SetOut(&out)
		apply.SetArgs([]string{"apply", profile})
		Expect(apply.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("applied generation 1"))

		// Status
		status := cli.NewRootCmd()
		out.Reset()
		status.SetOut(&out)
		status.SetArgs([]string{"status"})
		Expect(status.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("current generation: 1"))

		// Apply again -> generation 2
		apply2 := cli.NewRootCmd()
		out.Reset()
		apply2.SetOut(&out)
		apply2.SetArgs([]string{"apply", profile})
		Expect(apply2.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("applied generation 2"))

		// Rollback
		rb := cli.NewRootCmd()
		out.Reset()
		rb.SetOut(&out)
		rb.SetArgs([]string{"rollback"})
		Expect(rb.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("rolled back to generation 1"))

		// Status after rollback
		status2 := cli.NewRootCmd()
		out.Reset()
		status2.SetOut(&out)
		status2.SetArgs([]string{"status"})
		Expect(status2.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("current generation: 1"))
	})

	It("sets the manifest produced-by timestamp so age-based GC can compare", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := buildHelloPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		_, err := applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())

		dataHome := os.Getenv("XDG_DATA_HOME")
		f, err := os.Open(filepath.Join(dataHome, "polypkg", "generations", "1", "manifest.json"))
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		m, err := schema.ParseManifest(f)
		Expect(err).NotTo(HaveOccurred())
		Expect(m.ProducedBy.Timestamp.IsZero()).To(BeFalse(),
			"ProducedBy.Timestamp must be set so age-based GC can compare")
		Expect(m.ProducedBy.Timestamp.UTC()).To(BeTemporally("~", time.Now().UTC(), 30*time.Second))
	})
})
