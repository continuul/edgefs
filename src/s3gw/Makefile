SRCDIR = $(NEDGE_HOME)

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

GOPATH?=$(SRCDIR)/src

all: s3gw

s3gw: *.go */*.go
	GOPATH=$(GOPATH) CGO_LDFLAGS="-L$(SRCDIR)/lib $(DEBUG_LDFLAGS) -lccow -lccowutil -lnanomsg" \
		CGO_CFLAGS="$(DEBUG_FLAGS) -I$(SRCDIR)/include/ccow -I$(SRCDIR)/include" \
		go build -o s3gw main.go

install: s3gw
	mkdir -p $(DESTDIR)$(SRCDIR)/sbin
	cp -a s3gw $(DESTDIR)$(SRCDIR)/sbin
	mkdir -p $(DESTDIR)$(SRCDIR)/etc/ccow
	cp -a s3gw.json.example $(DESTDIR)$(SRCDIR)/etc/ccow

clean:
	rm -f s3gw
