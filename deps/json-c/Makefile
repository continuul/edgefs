#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)
NAME=json-c

.configure:
	cd ../.. && flock -e .gitmodules git submodule update --init deps/json-c/$(NAME)
	cd $(NAME) && ./autogen.sh
	cd $(NAME) && autoreconf --force --install
	cd $(NAME) && CFLAGS="$(CFLAGS) -g -O2" ./configure --prefix=$(SRCDIR)
	touch $@

.build: .configure
	make -C $(NAME)
	touch $@

install: .build
	make -C $(NAME) install
	rm -f $(SRCDIR)/lib/libjson-c.a

all: install

uninstall: .configure
	make -C $(NAME) uninstall

clean:
	rm -rf $(NAME); mkdir $(NAME)
	rm -f .configure .build
