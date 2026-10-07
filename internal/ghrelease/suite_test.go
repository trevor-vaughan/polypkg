package ghrelease

import (
	"path/filepath"
	"testing"

	ginkgo "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestGHRelease(t *testing.T) {
	RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "GHRelease Suite")
}

// The client reads no user files, but every spec still runs with HOME and
// the XDG base directories pointed at a fresh temp tree, so a regression
// that starts reading them cannot touch the invoking user's real state.
var _ = ginkgo.BeforeEach(func() {
	root := ginkgo.GinkgoT().TempDir()
	for _, env := range []string{
		"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
		"XDG_CACHE_HOME", "XDG_BIN_HOME", "XDG_RUNTIME_DIR",
		"XDG_CONFIG_DIRS", "XDG_DATA_DIRS",
	} {
		ginkgo.GinkgoT().Setenv(env, filepath.Join(root, env))
	}
})
