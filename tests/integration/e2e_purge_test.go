package integration

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// e2e_purge_test.go covers the purge confirmation gate: an inactive package
// must not be purged without --yes when stdin is not a terminal. The command's
// stdin is wired to a non-*os.File reader so isInteractive() is
// deterministically false (matching a piped/redirected stdin in production),
// whatever the test runner's own stdin is. The active-refuse and --yes success
// paths are already covered by e2e_state_test.go.
var _ = Describe("purge non-interactive confirmation", func() {
	It("refuses to purge an inactive package without --yes when stdin is not a terminal", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := helloStatePackage(t, "1.0.0")
		repoDir := t.TempDir()
		trust := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)

		_, err := applyHelloOnce(t, srv.URL, trust) // gen 1: hello active, state created
		Expect(err).NotTo(HaveOccurred())
		applyEmptyProfile(t) // hello now inactive, state preserved

		stateDir := filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "state", "hello")
		_, statErr := os.Stat(stateDir)
		Expect(statErr).NotTo(HaveOccurred(), "state dir must exist before the refused purge")

		cmd := purgeCmd("hello") // no --yes
		// A *strings.Reader is not an *os.File, so isInteractive() returns false:
		// this drives the non-terminal refusal path deterministically.
		cmd.SetIn(strings.NewReader(""))
		err = cmd.Execute()
		Expect(err).To(HaveOccurred(), "purge without --yes must refuse")
		Expect(err.Error()).To(ContainSubstring("purge needs confirmation but stdin is not a terminal"))

		_, statErr = os.Stat(stateDir)
		Expect(statErr).NotTo(HaveOccurred(), "state must be untouched after a refused purge")
	})
})
