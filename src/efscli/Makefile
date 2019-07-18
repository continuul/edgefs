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

TARGET := efscli
SRCS := main.go $(wildcard */*.go)

.PHONY: all clean

.get:
	GOPATH=`pwd` go get -v || true
	touch $@

$(TARGET): $(SRCS) .get
	GOPATH=`pwd` CGO_LDFLAGS="-L$(SRCDIR)/lib $(DEBUG_LDFLAGS) -lccow -lccowutil -lauditd -lccowfsio -lnanomsg" \
		CGO_CFLAGS="$(DEBUG_FLAGS) -I$(SRCDIR)/include/ccow -I$(SRCDIR)/include" \
		go build -o efscli main.go

fmt:
	gofmt -e -s -w bucket cluster config efsutil main.go service system \
		tenant validate object

clean:
	rm -rf $(TARGET) src .get

install: $(TARGET)
	mkdir -p $(DESTDIR)$(SRCDIR)/sbin 2> /dev/null || true
	cp -a $(TARGET) $(DESTDIR)$(SRCDIR)/sbin

all: install

uninstall:
	rm -f $(DESTDIR)$(SRCDIR)/sbin/$(TARGET)
