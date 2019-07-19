#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)
NAME=jemalloc

#
# To activate debug add these to configure
#
# remove
#
# --disable-fill \
#
# and add
#
# --enable-debug --enable-fill --disable-tcache \
#
# and modify util.c to remove use of lg_tcache_max (optional). Activate with:
#
# export JE_MALLOC_CONF=junk:true
#
# To activate memory leak detection, add this line to /opt/nedge/.local and
# restart service/daemons:
#
# export JE_MALLOC_CONF=prof:true,prof_prefix:jeprof.out,prof_leak:true,prof_gdump:true
#
.configure:
	cd ../.. && flock -e .gitmodules git submodule update --init deps/jemalloc/$(NAME)
	cd $(NAME) && ./autogen.sh
	cd $(NAME) && EXTRA_CFLAGS="-std=gnu99 -g -O3" CPPFLAGS=-O3 \
		./configure --prefix=$(SRCDIR) \
		--disable-valgrind \
		--disable-fill \
		--with-rpath=$(SRCDIR)/lib \
		--with-jemalloc-prefix=je_ --enable-prof
	touch $@

.build: .configure
	make -C $(NAME)
	touch $@

install: .build
	install -c -d $(DESTDIR)/$(SRCDIR)/bin
	install -c -m 755 $(NAME)/bin/jeprof $(DESTDIT)/$(SRCDIR)/bin
	install -c -d $(DESTDIR)/$(SRCDIR)/include/jemalloc
	install -c -m 644 $(NAME)/include/jemalloc/jemalloc.h $(DESTDIR)/$(SRCDIR)/include/jemalloc
	install -c -d $(DESTDIR)/$(SRCDIR)/lib
	install -c -m 755 $(NAME)/lib/libjemalloc.so.2 $(DESTDIR)/$(SRCDIR)/lib
	ln -sf libjemalloc.so.2 $(DESTDIR)/$(SRCDIR)/lib/libjemalloc.so

all: install

uninstall: .configure
	rm -f $(DESTDIR)/$(SRCDIR)/bin/jeprof
	rm -rf $(DESTDIR)/$(SRCDIR)/include/jemalloc
	rm -f $(DESTDIR)/$(SRCDIR)/lib/libjemalloc.so*

clean:
	rm -rf $(NAME); mkdir $(NAME)
	rm -f .configure .build
