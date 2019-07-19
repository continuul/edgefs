SRCDIR=$(NEDGE_HOME)

ifdef NEDGE_NDEBUG
DEBUG_FLAGS=-DUSE_JE_MALLOC
DEBUG_LDFLAGS=-ljemalloc -fno-omit-frame-pointer
else
DEBUG_FLAGS=-fsanitize=address -fno-omit-frame-pointer -fno-common

ifeq (${CC},clang)
DEBUG_LDFLAGS=-fsanitize=address
else
DEBUG_LDFLAGS=-lasan
endif

endif

TARGET := grpc-efsproxy
SRCS := main.go $(wildcard */*.go */*/*.go)

.PHONY: all clean

.get:
	GOPATH=$(SRCDIR)/src flock -e $(SRCDIR)/.lock go get -v || true
	GOPATH=$(SRCDIR)/src flock -e $(SRCDIR)/.lock go get github.com/golang/protobuf || true
	GOPATH=$(SRCDIR)/src flock -e $(SRCDIR)/.lock make -C $(SRCDIR)/src/src/github.com/golang/protobuf
	GOPATH=$(SRCDIR)/src flock -e $(SRCDIR)/.lock go get google.golang.org/grpc || true
	GOPATH=$(SRCDIR)/src flock -e $(SRCDIR)/.lock go get github.com/fullstorydev/grpcurl || true
	GOPATH=$(SRCDIR)/src flock -e $(SRCDIR)/.lock go install github.com/fullstorydev/grpcurl/cmd/grpcurl || true
	flock -e $(SRCDIR)/.lock ../../scripts/get-protobuf.sh
	touch $@

.proto: .get $(wildcard */*.proto)
	for d in cluster tenant service snapshot object; do \
		$(SRCDIR)/src/bin/protoc --proto_path=./$$d --plugin=$(SRCDIR)/src/bin/protoc-gen-go --go_out=plugins=grpc:$$d ./$$d/$$d.proto; \
	done
	touch $@

$(TARGET): $(SRCS) .get .proto
	GOPATH=$(SRCDIR)/src CGO_LDFLAGS="-L$(SRCDIR)/lib -lccow -lccowutil -lnanomsg -lccowfsio $(DEBUG_LDFLAGS)" \
		CGO_CFLAGS="$(DEBUG_FLAGS) -I$(SRCDIR)/include/ccow -I$(SRCDIR)/include" \
		go build -o grpc-efsproxy main.go

fmt:
	gofmt -e -s -w cluster efsutil main.go service tenant snapshot

clean:
	rm -rf $(TARGET) src .proto .get $(wildcard */*.pb.go)

install: $(TARGET)
	mkdir -p $(DESTDIR)$(SRCDIR)/sbin 2> /dev/null || true
	mkdir -p $(DESTDIR)$(SRCDIR)/lib/grpc-efsproxy 2> /dev/null || true
	cp -a $(TARGET) $(DESTDIR)$(SRCDIR)/sbin
	for d in cluster tenant service snapshot object; do \
		mkdir -p $(DESTDIR)$(SRCDIR)/lib/grpc-efsproxy/$$d 2> /dev/null || true; \
		cp $$d/*.pb.go $(DESTDIR)$(SRCDIR)/lib/grpc-efsproxy/$$d/; \
	done

all: install

uninstall:
	rm -f $(DESTDIR)$(SRCDIR)/sbin/$(TARGET)
	for d in cluster tenant service snapshot object; do \
		rm -rf $(DESTDIR)$(SRCDIR)/lib/grpc-efsproxy; \
	done
