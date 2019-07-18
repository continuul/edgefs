#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)
NAME=libqb

.configure:
	cd ../.. && flock --verbose -e .gitmodules git submodule update --init deps/libqb/$(NAME)
	cd $(NAME) && ./autogen.sh
	cd $(NAME) && ./configure --prefix=$(SRCDIR) \
		--with-socket-dir=$(SRCDIR)/var/run/corosync \
		--with-force-sockets-config-file=$(SRCDIR)/etc/corosync/unixsk \
		--enable-nosection-fallback
	touch $@

.build: .configure
	make -C $(NAME)
	touch $@

install: .build
	install -c -d $(SRCDIR)/var/run/corosync
	install -c -d $(SRCDIR)/etc/corosync
	make -C $(NAME)/include/qb install
	make -C $(NAME)/lib install
	rm -f $(SRCDIR)/lib/libqb.a

all: install

uninstall: .configure
	make -C $(NAME)/include/qb uninstall
	make -C $(NAME)/lib uninstall

clean:
	rm -rf $(NAME); mkdir $(NAME)
	rm -f .configure .build
