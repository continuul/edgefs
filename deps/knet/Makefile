#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)
NAME=kronosnet

.configure:
	cd ../.. && flock --verbose -e .gitmodules git submodule update --init deps/knet/$(NAME)
	cd $(NAME) && ./autogen.sh
	cd $(NAME) && libqb_BUILD_LIBS=$(SRCDIR)/lib libqb_BUILD_CFLAGS=$(SRCDIR)/include \
		./configure --prefix=$(SRCDIR) --disable-compress-all --enable-compress-zlib --disable-libknet-sctp --disable-man --disable-kronosnetd
	touch $@

.build: .configure
	make -C $(NAME)/libknet
	touch $@

install: .build
	make -C $(NAME)/libknet install
	rm -f $(SRCDIR)/lib/libknet.a

all: install

uninstall: .configure
	make -C $(NAME)/libknet uninstall

clean:
	rm -rf $(NAME); mkdir $(NAME)
	rm -f .configure .build
