#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)
NAME=corosync

.configure:
	cd ../.. && flock --verbose -e .gitmodules git submodule update --init deps/corosync/$(NAME)
	cd $(NAME) && ./autogen.sh
	cd $(NAME) && LIBQB_CFLAGS="-I$(SRCDIR)/include -DQB_KILL_ATTRIBUTE_SECTION" LIBQB_LIBS="-L$(SRCDIR)/lib -l:libqb.so.0" knet_CFLAGS="-I$(SRCDIR)/include" knet_LIBS="-L$(SRCDIR)/lib -lknet" ./configure --prefix=$(SRCDIR)
	touch $@

.build: .configure
	make -C $(NAME)
	touch $@

install: .build
	mkdir -p $(DESTDIR)$(SRCDIR)/var/lock/subsys
	make -C $(NAME) install
	cp corosync.conf.example.ipv4 $(DESTDIR)$(SRCDIR)/etc/corosync
	touch $(DESTDIR)$(SRCDIR)/etc/corosync/unixsk # force use of QB unix sockets
	rm -f $((DESTDIR)$(SRCDIR)/lib/libcfg.a
	rm -f $((DESTDIR)$(SRCDIR)/lib/libcorosync_common.a
	rm -f $((DESTDIR)$(SRCDIR)/lib/libquorum.a
	rm -f $((DESTDIR)$(SRCDIR)/lib/libtotem_pg.a
	rm -f $((DESTDIR)$(SRCDIR)/lib/libcmap.a
	rm -f $((DESTDIR)$(SRCDIR)/lib/libcpg.a
	rm -f $((DESTDIR)$(SRCDIR)/lib/libsam.a
	rm -f $((DESTDIR)$(SRCDIR)/lib/libvotequorum.a
	rm -f $((DESTDIR)$(SRCDIR)/bin/corosync-*

all: install

uninstall: .configure
	make -C $(NAME) uninstall

clean:
	rm -rf $(NAME); mkdir $(NAME)
	rm -f .configure .build
