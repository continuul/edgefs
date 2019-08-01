TARGET_LIB = libauth
TARGET_SRCS = json_path.c user.c acl.c auth.c bucket_options.c
#
# Activate by exporing this env variable:
#
# export ASAN_OPTIONS=symbolize=1:abort_on_error=1:disable_core=1:alloc_dealloc_mismatch=0:detect_leaks=1
#
ifndef NEDGE_NDEBUG
ASAN_CPPFLAGS=-fsanitize=address -fno-omit-frame-pointer -fno-common
ASAN_LDFLAGS=-fsanitize=address -fno-omit-frame-pointer -fno-common -lasan
endif
CFLAGS += -fPIC -pthread -std=gnu99 -Wall -Wstrict-aliasing=0 -Wendif-labels \
 -Wpointer-arith -Wbad-function-cast -Wcast-align -Wextra \
 -Wno-missing-field-initializers -Wno-unused-variable -Wno-unused-parameter \
 -Wno-cast-align -Wno-unused-function -D_GNU_SOURCE \
 -O2 -g -I. -I../../ccow/include -I../../ccow/src/include \
 -I/opt/nedge/include -I./include -I. -L. $(ASAN_CPPFLAGS)
LDFLAGS += -lccowutil -lccow -lutil -lnanomsg \
 -lz -ljemalloc -ljson-c $(ASAN_LDFLAGS)

TARGET_OBJS = $(TARGET_SRCS:.c=.o)

.PHONY: all
all: $(TARGET_LIB).a json_test user_test acl_test auth_test

$(TARGET_LIB).a: $(TARGET_OBJS)
	ar rcs $@ $^

json_test: $(TARGET_LIB).a json_test.o
	gcc -o $@ $^ $(TARGET_LIB).a $(LDFLAGS)

user_test: $(TARGET_LIB).a user_test.o
	gcc -o $@ $^ $(TARGET_LIB).a $(LDFLAGS)

acl_test: $(TARGET_LIB).a acl_test.o
	gcc -o $@ $^ $(TARGET_LIB).a $(LDFLAGS)

auth_test: $(TARGET_LIB).a auth_test.o
	gcc -o $@ $^ $(TARGET_LIB).a $(LDFLAGS)

clean:
	rm -f $(TARGET_LIB).a *.o json_test user_test acl_test auth_test
