#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)
NAME=libbacktrace

.configure:
	cd ../.. && flock -e .gitmodules git submodule update --init deps/libbacktrace/$(NAME)
	cd $(NAME) && CFLAGS="$(CFLAGS) -g -O2 -fPIC" ./configure --prefix=$(SRCDIR)
	touch $@

.build: .configure
	make -C $(NAME)
	touch $@

install: .build
	cp -ar $(NAME)/backtrace.h $(NAME)/backtrace-supported.h $(DESTDIR)$(SRCDIR)/include
	cp -ar $(NAME)/.libs/libbacktrace.a $(DESTDIR)$(SRCDIR)/lib/libbacktrace.a

all: install

uninstall: .configure
	rm -f $(SRCDIR)/lib/libbacktrace*
	rm -rf $(SRCDIR)/include/backtrace*
clean:
	rm -rf $(NAME); mkdir $(NAME)
	rm -f .configure .build
