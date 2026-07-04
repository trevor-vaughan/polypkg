package starlarkeval

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == ChildCommand {
		RunChild()
		return
	}
	os.Exit(m.Run())
}
