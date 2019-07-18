SRCDIR=$(NEDGE_HOME)
TARGET_BIN = ccowhttpd
TARGET_SRCS = ccowhttpd.c ccowobj.c objio.c param.c sig2auth.c putpub.c request_util.c session.c session_cache.c \
	sig4auth.c list_cache.c ccowobj_generator.c request.c s3_get.c s3_head.c \
	s3_bucket_create.c s3_bucket_head.c s3_bucket_delete.c s3_generator.c
TARGET_LIBAUTH = libauth
#
# Activate by exporing this env variable:
#
# export ASAN_OPTIONS=symbolize=1:abort_on_error=1:disable_core=1:alloc_dealloc_mismatch=0:detect_leaks=1
#
ifndef NEDGE_NDEBUG
ASAN_CPPFLAGS=-fsanitize=address -fno-omit-frame-pointer -fno-common -O0
ASAN_LDFLAGS=-fsanitize=address -fno-omit-frame-pointer -fno-common -lasan
else
ASAN_CPPFLAGS=-DUSE_JE_MALLOC -O2
ASAN_LDFLAGS=-ljemalloc -fno-omit-frame-pointer
endif
CFLAGS += $(ASAN_CPPFLAGS) -fPIC -pthread -std=gnu99 -Wall -Wstrict-aliasing=0 -Wendif-labels \
	  -Wpointer-arith -Wbad-function-cast -Wcast-align -Wextra \
	  -Wno-missing-field-initializers -Wno-unused-variable -Wno-unused-parameter \
	  -Wno-cast-align -Wno-unused-function -D_GNU_SOURCE \
	  -g -I. -I../ccow/include -I../ccow/src/include \
	  -I../ccow/src/libtrlog -Ih2o -DH2O_USE_EPOLL -L.
LDFLAGS += $(ASAN_LDFLAGS) -lccow -lccowutil -lnanomsg -ljemalloc -ljson-c \
	   -L$(NEDGE_HOME)/lib $(NEDGE_HOME)/lib/libh2o-evloop.a -lz -luuid -lpthread -lssl -lcrypto
LXFLAGS += $(ASAN_LDFLAGS) -lccow -lccowutil -lnanomsg -ljemalloc -ljson-c \
	   -L$(NEDGE_HOME)/lib $(NEDGE_HOME)/lib/libh2o-evloop.a \
	   -L$(NEDGE_HOME)/src/ccowhttpd/libauth/libauth.a \
	   -lz -luuid -lpthread -lssl -lcrypto

TARGET_OBJS = $(TARGET_SRCS:.c=.o)

.PHONY: all
all: $(TARGET_LIBAUTH)/libauth.a ${TARGET_BIN} install request_util_test uuid_util_test

$(TARGET_LIBAUTH):
	mkdir -p $@

$(TARGET_LIBAUTH)/libauth.a: $(TARGET_LIBAUTH)
	$(MAKE) -C $(TARGET_LIBAUTH)

$(TARGET_LIBAUTH)-clean:
	$(MAKE) -C $(TARGET_LIBAUTH) clean

$(TARGET_BIN): $(TARGET_OBJS) $(TARGET_LIBAUTH)/libauth.a
	gcc -o $@ $^ $(TARGET_LIBAUTH)/libauth.a $(LXFLAGS)

install: $(TARGET_BIN)
	mkdir -p $(DESTDIR)$(SRCDIR)/sbin 2> /dev/null || true
	cp -a fetch-ocsp-response $(DESTDIR)$(SRCDIR)/sbin
	cp -a $(TARGET_BIN) $(DESTDIR)$(SRCDIR)/sbin

uninstall:
	rm -f $(DESTDIR)$(SRCDIR)/sbin/fetch-ocsp-response
	rm -f $(DESTDIR)$(SRCDIR)/sbin/$(TARGET_BIN)

request_util_test: param.o request_util.o sig2auth.o request_util_test.o 
	gcc -o $@ $^ -L. $(LDFLAGS)

uuid_util_test: uuid_util_test.o 
	gcc -o $@ $^ -L. $(LDFLAGS)
	
clean: $(TARGET_LIBAUTH)-clean
	rm -f $(TARGET_BIN) *.o request_util_test uuid_util_test
