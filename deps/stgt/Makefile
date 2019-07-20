#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)
NAME=tgt

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

.configure:
	cd ../.. && flock -e .gitmodules git submodule update --init deps/stgt/$(NAME)
	touch $@

.build: .configure
	PREFIX=$(SRCDIR) CFLAGS="$(CFLAGS) $(DEBUG_FLAGS)" \
	       LDFLAGS="$(LDFLAGS) $(DEBUG_LDFLAGS)" LIBS="$(DEBUG_LDFLAGS)" \
		make -C $(NAME) CCOWBD=1 programs
	touch $@

install: .build
	mkdir -p $(SRCDIR)/usr
	make -C $(NAME)/usr CCOWBD=1 DESTDIR=$(DESTDIR)$(SRCDIR) install
	chmod +x $(NAME)/start.sh
	cp $(NAME)/start.sh $(SRCDIR)/sbin/tgt_lun.sh

all: install

uninstall: .build
	rm -f $(SRCDIR)/sbin/{tgtd,tgtadm,tgtimg,start.sh}

clean:
	rm -rf $(NAME); mkdir $(NAME)
	rm -f .configure .build
