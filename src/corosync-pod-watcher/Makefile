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

TARGET := corosync-pod-watcher
SRCS := main.go $(wildcard */*.go)
GOPATH?=$(SRCDIR)/src

.PHONY: all clean

.get:
	GOPATH=$(GOPATH) flock -e $(SRCDIR)/.lock go mod download || true
	touch $@

$(TARGET): $(SRCS) .get
	GOPATH=$(GOPATH)  CGO_LDFLAGS="-L$(SRCDIR)/lib $(DEBUG_LDFLAGS) -lccow -lccowutil -lauditd -lccowfsio -lnanomsg" \
		CGO_CFLAGS="$(DEBUG_FLAGS) -I$(SRCDIR)/include/ccow -I$(SRCDIR)/include" \
		go build -o $(TARGET) main.go

fmt:
	gofmt -e -s -w main.go

clean:
	rm -rf $(TARGET) .get

install: $(TARGET)
	mkdir -p $(DESTDIR)$(SRCDIR)/sbin 2> /dev/null || true
	cp -a $(TARGET) $(DESTDIR)$(SRCDIR)/sbin

all: install

uninstall:
	rm -f $(DESTDIR)$(SRCDIR)/sbin/$(TARGET)
