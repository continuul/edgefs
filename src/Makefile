#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)
PROJECTS_DIRS_PROXY_DEPS=grpc-iscsi grpc-nfs s3gw grpc-s3x grpc-s3
PROJECTS_DIRS=efscli ccownbd ccowhttpd grpc-efsproxy corosync-pod-watcher

MAKEFLAGS += -j

all: install

.ccow-configure:
	cd ccow; test -f ccow/configure || ./autogen.sh; \
		if test x$(NEDGE_NDEBUG) = x1; then \
			./configure --prefix=$(NEDGE_HOME) \
				    --enable-silent-rules \
				    --disable-address-sanitizer \
				    --disable-debug; \
		else \
			./configure --prefix=$(NEDGE_HOME) \
				    --enable-silent-rules; \
		fi; \
		cd -
	touch $@

.ccow-build: .ccow-configure
	make -C ccow
	touch $@

.ccow: .ccow-build
	make -C ccow install
	touch $(SRCDIR)/.lock

$(PROJECTS_DIRS_PROXY_DEPS):: .ccow
	$(MAKE) -C $@ $(MAKECMDGOALS)

$(PROJECTS_DIRS):: .ccow $(PROJECTS_DIRS_PROXY_DEPS)
	$(MAKE) -C $@ $(MAKECMDGOALS)

# note that .grpc-PROTOCOL needs to be first in this order
# as .grpc-efsproxy needs .proto interfaces from it
install: .ccow $(PROJECTS_DIRS_PROXY_DEPS) $(PROJECTS_DIRS)
	-mkdir -p $(DESTDIR)$(SRCDIR)/var/run
	-mkdir -p $(DESTDIR)$(SRCDIR)/var/cores
	rm -f $(DESTDIR)$(SRCDIR)/lib/libauditd.a
	rm -f $(DESTDIR)$(SRCDIR)/lib/libblake2_avx2.a
	rm -f $(DESTDIR)$(SRCDIR)/lib/libblake2_avx.a
	rm -f $(DESTDIR)$(SRCDIR)/lib/libblake2_simd.a
	rm -f $(DESTDIR)$(SRCDIR)/lib/libblake2_sse41.a
	rm -f $(DESTDIR)$(SRCDIR)/lib/libccow.a
	rm -f $(DESTDIR)$(SRCDIR)/lib/libccowd.a
	rm -f $(DESTDIR)$(SRCDIR)/lib/libccowfsio.a
	rm -f $(DESTDIR)$(SRCDIR)/lib/libccowutil.a
	rm -f $(DESTDIR)$(SRCDIR)/lib/libccowvol.a
	rm -f $(DESTDIR)$(SRCDIR)/lib/libconnbroker.a
	rm -f $(DESTDIR)$(SRCDIR)/lib/libkvsfs_backend.a
	rm -f $(DESTDIR)$(SRCDIR)/lib/libkvslmdb_backend.a
	rm -f $(DESTDIR)$(SRCDIR)/lib/librtkvs.a
	rm -f $(DESTDIR)$(SRCDIR)/lib/librtlfs.a
	rm -f $(DESTDIR)$(SRCDIR)/lib/librtrd.a

uninstall: .ccow-configure
	-make -C ccow uninstall
	for p in $(PROJECTS_DIRS) $(PROJECTS_DIRS_PROXY_DEPS); do make -C $$p uninstall || exit 1; done

clean:
	-make -C ccow clean
	for p in $(PROJECTS_DIRS) $(PROJECTS_DIRS_PROXY_DEPS); do make -C $$p clean || exit 1; done
	rm -f .ccow-configure .ccow-build
	rm -rf ./pkg ./bin ./src
