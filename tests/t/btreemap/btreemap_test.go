package btreemap_test

import (
	"os"
	"os/exec"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

func TestBtreemap(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Libchunk BTree Map Suite")
}

var _ = Describe("BTreemap", func() {
	It("algorithm check should pass", func() {
		cmd := exec.Command("btree_test")
		_, err := gexec.Start(cmd, os.Stdout, os.Stdout)
		Expect(err).ShouldNot(HaveOccurred())
	})
})
