#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)
NAME=smartmontools

.configure:
	cd ../.. && flock -e .gitmodules git submodule update --init deps/smartmontools/$(NAME)
	cd $(NAME)/smartmontools && ./autogen.sh && ./configure --prefix=$(SRCDIR) --with-nvme-devicescan
	touch $@

.build: .configure
	PREFIX=$(SRCDIR) make -C $(NAME)/smartmontools
	touch $@

install: .build
	cp $(NAME)/smartmontools/smartctl $(DESTDIR)$(SRCDIR)/sbin

all: install

uninstall: .configure
	rm -f $(DESTDIR)$(SRCDIR)/sbin

clean:
	rm -rf $(NAME); mkdir $(NAME)
	rm -f .configure .build
