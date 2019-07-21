#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)
NAME=fio

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
	cd ../.. && flock -e .gitmodules git submodule update --depth 1 --recursive --init deps/fio/$(NAME)
	cd $(NAME) && ./configure --prefix=$(SRCDIR)
	touch $@

.build: .configure
	PREFIX=$(SRCDIR) EXTFLAGS="$(CFLAGS) $(DEBUG_FLAGS)" \
	LDFLAGS="$(LDFLAGS) $(DEBUG_LDFLAGS)" LIBS="$(DEBUG_LDFLAGS)" \
	make -C $(NAME) 
	touch $@

install: .build
	make -C $(NAME) install

all: install

uninstall: .configure
	make -C $(NAME) uninstall

clean:
	rm -rf $(NAME); mkdir $(NAME)
	rm -f .configure .build
