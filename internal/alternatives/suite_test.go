package alternatives_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAlternatives(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Alternatives Suite")
}
