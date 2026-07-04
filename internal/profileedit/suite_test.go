package profileedit

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestProfileEdit(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ProfileEdit Suite")
}
