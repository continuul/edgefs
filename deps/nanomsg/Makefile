#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)
NAME=nanomsg

.configure:
	cd ../.. && flock -e .gitmodules git submodule update --depth 1 --recursive --init deps/nanomsg/$(NAME)
	cd $(NAME) && ./autogen.sh
	cd $(NAME) && CFLAGS="$(CFLAGS) -g -O0" ./configure --prefix=$(SRCDIR)
	touch $@

.build: .configure
	make -C $(NAME)
	touch $@

install: .build
	make -C $(NAME) install
	rm -f $(SRCDIR)/lib/libnanomsg.a $(SRCDIR)/bin/nn_* $(SRCDIR)/bin/tcpmuxd

all: install

uninstall: .configure
	make -C $(NAME) uninstall

clean:
	rm -rf $(NAME); mkdir $(NAME)
	rm -f .configure .build
