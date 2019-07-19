#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)
NAME=h2o

ifdef NEDGE_NDEBUG
DEBUG_FLAGS=-DUSE_JE_MALLOC
DEBUG_LDFLAGS=-ljemalloc -fno-omit-frame-pointer
else
DEBUG_FLAGS=-fsanitize=address -fno-omit-frame-pointer -fno-common
DEBUG_LDFLAGS=-lasan
endif

.configure:
	cd ../.. && flock -e .gitmodules git submodule update --init deps/h2o/$(NAME)
	cd $(NAME) && CFLAGS="$(CFLAGS) $(DEBUG_FLAGS)" LDFLAGS="$(LDFLAGS) $(DEBUG_LDFLAGS)" cmake -DWITH_MRUBY=OFF -DWITH_PICOTLS=ON CMakeLists.txt
	touch $@

.build: .configure
	cd $(NAME) && make libh2o-evloop
	touch $@

install: .build
	cd $(NAME) && cp -ar include/h2o $(SRCDIR)/include
	cd $(NAME) && cp -ar include/h2o.h $(SRCDIR)/include
	cd $(NAME) && cp -ar deps/yoml/yoml.h $(SRCDIR)/include
	cd $(NAME) && cp -ar deps/picotls/include/picotls* $(SRCDIR)/include
	cd $(NAME) && cp libh2o-evloop.a $(SRCDIR)/lib

all: install

uninstall: .configure
	rm -rf $(SRCDIR)/include/h2o*
	rm -f $(SRCDIR)/lib/libh2o-evloop.a

clean:
	rm -rf $(NAME); mkdir $(NAME)
	rm -f .configure .build
