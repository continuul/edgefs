#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)

all: install

install:
	cp liveness.sh readiness.sh edgefs-stop.sh edgefs-start.sh grpc-proxy-liveness.sh $(DESTDIR)$(SRCDIR)/sbin/
	cp auditctl $(DESTDIR)$(SRCDIR)/etc/init.d/
	cp sysctl*.conf $(DESTDIR)$(SRCDIR)/etc/

uninstall:
	rm -f	$(DESTDIR)$(SRCDIR)/sbin/edgefs-start.sh \
		$(DESTDIR)$(SRCDIR)/sbin/edgefs-stop.sh \
		$(DESTDIR)$(SRCDIR)/sbin/grpc-proxy-liveness.sh \
		$(DESTDIR)$(SRCDIR)/sbin/liveness.sh \
		$(DESTDIR)$(SRCDIR)/sbin/readiness.sh \
		$(DESTDIR)$(SRCDIR)/etc/init.d/auditctl \
		$(DESTDIR)$(SRCDIR)/etc/sysctl.conf

clean:
