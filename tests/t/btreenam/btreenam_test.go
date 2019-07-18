package btreenam_test

import (
	"os"
	"os/exec"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

func TestBtreenam(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Libchunk BTree NameIndex Suite")
}

var _ = Describe("BTreemap", func() {
	It("algorithm check should pass", func() {
		cmd := exec.Command("btree_test")
		_, err := gexec.Start(cmd, os.Stdout, os.Stdout)
		Expect(err).ShouldNot(HaveOccurred())
	})
})
