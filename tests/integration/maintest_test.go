package integration

import (
	"os"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/starlarkeval"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == starlarkeval.ChildCommand {
		starlarkeval.RunChild()
		return
	}
	os.Exit(m.Run())
}
