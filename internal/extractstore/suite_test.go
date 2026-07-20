package extractstore_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestExtractStore(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ExtractStore Suite")
}
