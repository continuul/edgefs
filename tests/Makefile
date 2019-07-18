SRCDIR=$(NEDGE_HOME)

TARGET := test
SRCS := $(wildcard */*.go)

.PHONY: all clean

.get:
	GOPATH=`pwd` go get -u github.com/onsi/ginkgo/ginkgo
	GOPATH=`pwd` go get -u github.com/onsi/gomega/...
	touch $@

$(TARGET): $(SRCS) .get
	GOPATH=`pwd` bin/ginkgo $(T) -r ./t

fmt:
	gofmt -e -s -w .

clean:
	rm -rf $(TARGET) src .get bin

install: $(TARGET)

all: install

uninstall:
