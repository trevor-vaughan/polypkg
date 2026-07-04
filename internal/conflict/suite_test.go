package conflict_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestConflict(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Conflict Suite")
}
