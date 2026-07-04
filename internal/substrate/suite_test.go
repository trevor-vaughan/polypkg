package substrate

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSubstrate(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Substrate Suite")
}
