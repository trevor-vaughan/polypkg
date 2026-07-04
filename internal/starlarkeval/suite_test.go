package starlarkeval

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestStarlarkEval(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "StarlarkEval Suite")
}
