#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)
NAME=libuv

.configure:
	cd ../.. && flock -e .gitmodules git submodule update --init deps/libuv/$(NAME)
	cd $(NAME) && CFLAGS="-O3 -funroll-loops -ggdb3" make
	touch $@

.build: .configure
	make -C $(NAME)
	touch $@

install: .build
	cp -ar $(NAME)/include/* $(DESTDIR)$(SRCDIR)/include
	cp -ar $(NAME)/libuv.so $(DESTDIR)$(SRCDIR)/lib/libuv.so.0.10.0
	ln -sf libuv.so.0.10.0 $(DESTDIR)$(SRCDIR)/lib/libuv.so.0.10
	ln -sf libuv.so.0.10 $(DESTDIR)$(SRCDIR)/lib/libuv.so

all: install

uninstall: .configure
	rm -f $(SRCDIR)/lib/libuv*
	rm -rf $(SRCDIR)/include/uv*
clean:
	rm -rf $(NAME); mkdir $(NAME)
	rm -f .configure .build
