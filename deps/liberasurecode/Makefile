#
# Use is subject of licensing terms
# Nexenta Systems, Inc.
#

SRCDIR=$(NEDGE_HOME)
YASM_NAME=yasm
ISAL_NAME=isa-l
GF_NAME=gf-complete
JE_NAME=jerasure
EC_NAME=liberasurecode
MAKEFLAGS += -j

.build_dep:
	cd ../.. && flock -e .gitmodules git submodule update --depth 1 --recursive --init deps/liberasurecode/$(YASM_NAME)
	cd ../.. && flock -e .gitmodules git submodule update --depth 1 --recursive --init deps/liberasurecode/$(ISAL_NAME)
	cd ../.. && flock -e .gitmodules git submodule update --depth 1 --recursive --init deps/liberasurecode/$(GF_NAME)
	cd ../.. && flock -e .gitmodules git submodule update --depth 1 --recursive --init deps/liberasurecode/$(JE_NAME)
	cd ../.. && flock -e .gitmodules git submodule update --depth 1 --recursive --init deps/liberasurecode/$(EC_NAME)
	cd $(YASM_NAME) && ./autogen.sh
	cd $(YASM_NAME) && ./configure --prefix=$(SRCDIR)
	make -j1 install -C $(YASM_NAME)
	cd $(GF_NAME) && ./autogen.sh && ./configure --prefix=$(SRCDIR) --disable-avx
	make install -C $(GF_NAME)
	touch $@

.configure: .build_dep
	cd $(JE_NAME) && ./autogen.sh && ./configure --prefix=$(SRCDIR) --disable-avx
	cd $(EC_NAME) && ./autogen.sh && ./configure --prefix=$(SRCDIR) --disable-avx
	cd $(ISAL_NAME) && ./autogen.sh && ./configure --prefix=$(SRCDIR)
	touch $@

.build: .configure
	make -C $(JE_NAME)
	make -C $(ISAL_NAME)
	make -C $(EC_NAME)
	touch $@

install: .build
	make install -C $(GF_NAME)
	make install -C $(JE_NAME)
	TOPDIR=$(SRCDIR) make install -C $(ISAL_NAME)
	make install -C $(EC_NAME)
	rm -f $(SRCDIR)/lib/liberasurecode.a
	rm -f $(SRCDIR)/lib/liberasurecode_rs_vand.a
	rm -f $(SRCDIR)/lib/libgf_complete.a
	rm -f $(SRCDIR)/lib/libisal.a
	rm -f $(SRCDIR)/lib/libJerasure.a
	rm -f $(SRCDIR)/lib/libnullcode.a
	rm -f $(SRCDIR)/lib/libXorcode.a
	rm -f $(SRCDIR)/lib/libyasm.a
	rm -f $(SRCDIR)/bin/cauchy_* $(SRCDIR)/bin/gf_* $(SRCDIR)/bin/liberation_* \
		$(SRCDIR)/bin/jerasure_* $(SRCDIR)/bin/reed_sol_* \
		$(SRCDIR)/bin/decoder $(SRCDIR)/bin/encoder \
		$(SRCDIR)/bin/vsyasm $(SRCDIR)/bin/yasm $(SRCDIR)/bin/ytasm

all: install

uninstall: .patch
	make -C $(GF_NAME) uninstall
	make -C $(JE_NAME) uninstall
	make -C $(EC_NAME) uninstall
	make -C $(YASM_NAME) uninstall
	TOPDIR=$(SRCDIR) make -C isa-l_open_src_$(ISAL_VER) uninstall
clean:
	rm -rf $(JE_NAME) $(GF_NAME) $(YASM_NAME) $(EC_NAME) $(ISAL_NAME)
	mkdir $(JE_NAME) $(GF_NAME) $(YASM_NAME) $(EC_NAME) $(ISAL_NAME)
	rm -f .build_dep .configure .build
