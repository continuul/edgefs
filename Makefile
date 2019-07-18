#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

distributorid=$(shell echo $$(. /etc/os-release; echo $$ID | tr '[A-Z]' '[a-z]'))
versionid=$(shell echo $$(. /etc/os-release; echo $$VERSION_ID | tr '[A-Z]' '[a-z]'))
osarch=$(shell uname -m)
uid=$(shell id -u)

VERSION := 1.0.0

DESTDIR ?= $(NEDGE_HOME)

define verify_minimal_env
@test x$(NEDGE_HOME) != x || (echo Error: NEDGE_HOME is not set; false)
@test $(distributorid) = ubuntu -o $(distributorid) = centos -o $(distributorid) = rhel || \
	(echo Error: unsupported distribution "$(distributorid)"; false)
endef

define install_dev_env
@if test $(distributorid) = ubuntu; then \
	apt-get update; \
	apt-get -y install git curl; \
fi
@if test $(distributorid) = centos -o $(distributorid) = rhel; then \
	yum -y install git cscope yasm wget; \
fi
@if [ ! -f /usr/bin/go ]; then \
	echo; \
	echo "/usr/bin/go not found: installing local copy of golang"; \
	echo; \
	cd /usr/local; \
	curl https://dl.google.com/go/go1.12.7.linux-amd64.tar.gz --output go1.12.7.linux-amd64.tar.gz --silent ; \
	tar -xf go1.12.7.linux-amd64.tar.gz; \
	rm -f go1.12.7.linux-amd64.tar.gz; \
	cd -; \
	ln -s /usr/local/go/bin/go /usr/bin/go; \
fi
endef

define install_lib_deps
@if test $(distributorid) = ubuntu; then \
	apt-get -y install build-essential libtool automake cmake uuid-dev \
		cgroup-bin systemtap-sdt-dev libcurl4-openssl-dev libkrb5-dev \
		libblkid-dev libnss3-dev groff libssl-dev libcgroup-dev \
		bison flex curl unzip udev zlib1g-dev libtirpc-dev rpcbind \
		libnl-route-3-dev pkg-config; \
fi
@if test $(distributorid) = centos -o $(distributorid) = rhel; then \
	yum -y --skip-broken install openssl-devel libtool automake cmake \
		systemtap-sdt-devel curl-devel libcgroup-devel libuuid-devel \
		libcgroup-tools libasan devtoolset-4-libasan-devel \
		libblkid-devel nss-devel groff-base openssl-devel \
		libcgroup-devel krb5-devel bison flex curl unzip udev; \
	yum -y install --enablerepo=rhel-7-server-optional-rpms; \
	yum -y groupinstall "Development Tools"; \
	yum -y install centos-release-scl; \
	yum -y install devtoolset-4-gcc*; \
	if test -f /usr/bin/gcc; then \
		mv /usr/bin/g++ /usr/bin/g++-4; \
		mv /usr/bin/gcc /usr/bin/gcc-4; \
		mv /usr/bin/c++ /usr/bin/c++-4; \
		ln -s /opt/rh/devtoolset-4/root/usr/bin/g++ /usr/bin/g++; \
		ln -s /opt/rh/devtoolset-4/root/usr/bin/c++ /usr/bin/c++; \
		ln -s /opt/rh/devtoolset-4/root/usr/bin/gcc /usr/bin/gcc; \
	fi \
fi
endef


all:
	$(call verify_minimal_env)
	@echo
	@echo Installation path: $(NEDGE_HOME)
	@echo
	@echo Available commands:
	@echo
	@echo "make deps               - build and install all dependencies"
	@echo "make edgefs             - build and install all components"
	@echo "make test               - build and install all tests"
	@echo "make tools              - build and install all tools"
	@echo "make world              - build and install everything (needs root privs)"
	@echo "make docs               - build APIs documentation"
	@echo "make cscope             - build cscope cross-reference for ./src"
	@echo "make uninstall          - uninstall all components"
	@echo "make deploy             - deploy development dependencies"
	@echo "make clean              - clean up the old build"
	@echo

cscope:
	$(call verify_minimal_env)
	cd src && \
		cscope -q -b -R -P $(NEDGE_HOME)/src
	cd src && \
		cscope -q -b -R -P $(NEDGE_HOME)/deps -s$(NEDGE_HOME)/deps

docs:
	$(call verify_minimal_env)
	cd src/ccow && \
		rm -rf latex html; \
		doxygen doxygen.conf; \
		cd latex && make pdf
	mv src/ccow/latex/refman.pdf ccow.pdf
	rm -rf src/ccow/latex
	mv src/ccow/html .

clean:
	$(call verify_minimal_env)
	make -C src clean
	make -C deps clean
	rm -f .deploy .deploy-dev .ccow-test .ccow-tools .deps .edgefs .scripts
	@echo
	@echo ==============================================
	@echo " EdgeFS is ready to run 'make install' again "
	@echo ==============================================

.deploy-dev:
	$(call verify_minimal_env)
	$(call install_dev_env)
	touch $@
deploy-dev: .deploy-dev

.deploy:
	$(call verify_minimal_env)
	$(call install_lib_deps)
	touch $@
deploy: deploy-dev .deploy
	@echo
	@echo ==============================================================================
	@echo "                   All package dependencies deployed."
	@echo ==============================================================================

.deps:
	make -C deps
	touch $@
deps: .deps

.edgefs: deps
	make -C src install
	make -C deps ccow-deps
	touch $@
edgefs: .deps .edgefs

.scripts:
	make -C scripts install
	touch $@
scripts: .scripts

world: deploy edgefs tools scripts
	@-cp -f env.sh $(NEDGE_HOME)/
	@test ! -e $(NEDGE_HOME)/.local && \
	if test "x$(NEDGE_VERSION)" = x; then \
		echo "export NEDGE_VERSION=$(VERSION)" > $(NEDGE_HOME)/.local; \
	else \
		echo "export NEDGE_VERSION=$(NEDGE_VERSION)" > $(NEDGE_HOME)/.local; \
	fi || true
	@echo
	@echo ==============================================================================
	@echo "                              All compiled."
	@echo ==============================================================================

.ccow-test: .edgefs
	make -j -C src/ccow/test install
	touch $@

test: .ccow-test
	@echo
	@echo ==============================================================================
	@echo "                           All tests compiled."
	@echo ==============================================================================

.ccow-tools: .edgefs
	make -j -C src/ccow/tools install
	touch $@

tools: .ccow-tools
	@echo
	@echo ==============================================================================
	@echo "                           All tools compiled."
	@echo ==============================================================================

install: deploy
	make -C src install
	make -C src/ccow/test install
	make -C src/ccow/tools install
	make -C deps
	make -C deps ccow-deps

uninstall: deploy
	make -C deps uninstall
	make -C deps ccow-deps uninstall
	make -C src/ccow/tools uninstall
	make -C src/ccow/test uninstall
	make -C src uninstall
	make -C scripts uninstall
