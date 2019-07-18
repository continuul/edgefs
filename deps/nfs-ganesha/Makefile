#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

# libntirpc-dev
SRCDIR=$(NEDGE_HOME)
NAME=nfs-ganesha
NFS_UTILS=nfs-utils

FSAL_DESTINATION?=/lib/ganesha

ifdef NEDGE_NDEBUG
DEBUG_FLAGS=-DUSE_JE_MALLOC
DEBUG_LDFLAGS=-fno-omit-frame-pointer
GAN_ALLOCATOR=jemalloc
else
DEBUG_FLAGS=-fsanitize=address -fno-omit-frame-pointer -fno-common
DEBUG_LDFLAGS=-lasan
GAN_ALLOCATOR=libc
endif

all: install

.configure:
	cd ../.. && flock --verbose -e .gitmodules git submodule update --init deps/nfs-ganesha/$(NAME)
	cd ../.. && flock --verbose -e .gitmodules git submodule update --init deps/nfs-ganesha/$(NFS_UTILS)
	cd $(NAME) && git submodule update --init src/libntirpc
	mkdir -p build
	cd build && env JEMALLOC_ROOT_DIR=$(SRCDIR) CFLAGS="$(CFLAGS) $(DEBUG_FLAGS)" \
				    LDFLAGS="$(LDFLAGS) $(DEBUG_LDFLAGS) -lpthread" cmake \
	    -DCMAKE_BUILD_TYPE=Debug \
	    -DUSE_FSAL_NEDGE=ON \
	    -DUSE_FSAL_PROXY=OFF \
	    -DUSE_FSAL_VFS=OFF \
	    -DUSE_FSAL_CEPH=OFF \
	    -DUSE_FSAL_GPFS=OFF \
	    -DUSE_FSAL_ZFS=OFF \
	    -DUSE_FSAL_LUSTRE=OFF \
	    -DUSE_FSAL_XFS=OFF \
	    -DUSE_FSAL_GLUSTER=OFF \
	    -DUSE_FSAL_PT=OFF \
	    -DUSE_FSAL_MEM=OFF \
	    -DUSE_ADMIN_TOOLS=OFF \
	    -DUSE_LTTNG=OFF \
	    -DUSE_TIRPC_IPV6=ON \
	    -DUSE_9P=OFF \
	    -DUSE_9P_RDMA=OFF \
	    -D_USE_9P_RDMA=OFF \
	    -DUSE_CONTROL_SOCKET=ON \
	    -DCMAKE_INSTALL_BINDIR=$(SRCDIR)/sbin \
	    -DLIB_INSTALL_DIR=$(SRCDIR)/lib \
	    -DJEMALLOC_ROOT_DIR=$(SRCDIR) \
	    -DALLOCATOR=$(GAN_ALLOCATOR) \
	    -DNEDGE_PREFIX=$(SRCDIR) \
	    -DCMAKE_INSTALL_PREFIX=$(SRCDIR) \
	    -DMODULES_PATH=$(SRCDIR) \
	    ../$(NAME)/src/
	touch $@

.build: .configure
	make VERBOSE=1 -C build
	touch $@

.utils_build: .configure
	cd $(NFS_UTILS); ./autogen.sh
	cd $(NFS_UTILS) && LIBTIRPC="-lntirpc" ./configure --disable-nfsv4 --disable-nfsv41 \
		--with-tirpcinclude=$(NAME)/src/libntirpc/ntirpc \
		--disable-gss --with-statedir=$(SRCDIR)/var/lib/nfs \
		--with-statdpath=$(SRCDIR)/var/lib/nfs
	make -C $(NFS_UTILS)
	touch $@

install_ganesha: .build
	make -C build install
	mv $(DESTDIR)$(SRCDIR)/bin/ganesha.nfsd $(DESTDIR)$(SRCDIR)/sbin
	mkdir -p $(DESTDIR)$(SRCDIR)/etc/ganesha/exports
	mkdir -p $(DESTDIR)$(SRCDIR)/var/lib/nfs/sm
	touch $(DESTDIR)$(SRCDIR)/etc/ganesha/exportslist
	cp ganesha.conf $(DESTDIR)$(SRCDIR)/etc/ganesha/ganesha.conf

install_utils: .utils_build
	install -o root -g root -m 755 ./$(NFS_UTILS)/utils/statd/statd $(DESTDIR)$(SRCDIR)/sbin/rpc.statd
	install -o root -g root -m 755 ./$(NFS_UTILS)/utils/statd/sm-notify $(DESTDIR)$(SRCDIR)/sbin/sm-notify

install: install_ganesha install_utils

clean:
	rm -rf .configure .build .utils_build build
	rm -rf $(NAME); mkdir $(NAME)
	rm -rf $(NFS_UTILS); mkdir $(NFS_UTILS)


