package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/cli"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("pin", func() {
	It("pin happy path persists a pin record on the generation", func() {
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

		root := cli.NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"generation", "pin", "1", "--reason", "baseline"})
		Expect(root.Execute()).To(Succeed())

		dataHome := os.Getenv("XDG_DATA_HOME")
		pinPath := filepath.Join(dataHome, "polypkg", "generations", "1", "pin.json")
		f, err := os.Open(pinPath)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		p, err := schema.ParsePin(f)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Generation).To(Equal(1))
		Expect(p.PinnedReason).To(Equal("baseline"))
		Expect(p.PinnedBy).NotTo(BeEmpty())
	})

	It("unpin happy path removes the pin record", func() {
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

		root := cli.NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"generation", "pin", "1", "--reason", "x"})
		Expect(root.Execute()).To(Succeed())

		root = cli.NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"generation", "unpin", "1"})
		Expect(root.Execute()).To(Succeed())

		dataHome := os.Getenv("XDG_DATA_HOME")
		_, err = os.Stat(filepath.Join(dataHome, "polypkg", "generations", "1", "pin.json"))
		Expect(os.IsNotExist(err)).To(BeTrue(), "pin.json should be gone after unpin")
	})

	It("pinning an already-pinned generation errors", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := buildHelloPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())

		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"generation", "pin", "1"})
		Expect(cmd.Execute()).To(Succeed())

		cmd = cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"generation", "pin", "1"})
		Expect(cmd.Execute()).To(HaveOccurred())
	})

	It("pinning a non-existent generation errors", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := buildHelloPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())

		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"generation", "pin", "9999"})
		Expect(cmd.Execute()).To(HaveOccurred())
	})

	It("unpinning an unpinned generation succeeds as a no-op", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := buildHelloPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()
		_, err := applyHelloOnce(t, srv.URL, trustRoot)
		Expect(err).NotTo(HaveOccurred())

		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"generation", "unpin", "1"})
		Expect(cmd.Execute()).To(Succeed(), "unpinning an unpinned gen should succeed (no-op)")
	})
})
