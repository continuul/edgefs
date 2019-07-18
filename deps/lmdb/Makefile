#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)
NAME=lmdb
ifeq (x$(NEDGE_NDEBUG),x1)
JEMALLOC=yes
DFLAGS=-DNDEBUG
else
JEMALLOC=no
endif

.build:
	cd ../.. && flock --verbose -e .gitmodules git submodule update --init deps/lmdb/$(NAME)
	XCFLAGS="$(XCFLAGS) $(DFLAGS) -DMDB_USE_ROBUST -DMDB_USE_PWRITEV=1 -DMDB_FDATASYNC_WORKS=1 -DMADV_RANDOM=1" USE_JEMALLOC=$(JEMALLOC) \
		 make -C $(NAME)/libraries/liblmdb prefix=$(SRCDIR)
	touch $@

install: .build
	mkdir -p $(DESTDIR)$(SRCDIR)/sbin
	cp $(NAME)/libraries/liblmdb/liblmdb.so $(DESTDIR)$(SRCDIR)/lib
	cp $(NAME)/libraries/liblmdb/lmdb.h $(DESTDIR)$(SRCDIR)/include
	cp $(NAME)/libraries/liblmdb/mdb_stat $(DESTDIR)$(SRCDIR)/sbin
	cp $(NAME)/libraries/liblmdb/mdb_copy $(DESTDIR)$(SRCDIR)/sbin

all: install

uninstall:
	rm -f $(DESTDIR)$(SRCDIR)/lib/liblmdb.so
	rm -f $(DESTDIR)$(SRCDIR)/include/lmdb.h

clean:
	rm -rf $(NAME); mkdir $(NAME)
	rm -f .build
