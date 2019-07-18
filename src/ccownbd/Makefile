SRCDIR=$(NEDGE_HOME)

ifdef NEDGE_NDEBUG
DEBUG_FLAGS=-DUSE_JE_MALLOC
DEBUG_LDFLAGS=-ljemalloc -fno-omit-frame-pointer
else
DEBUG_FLAGS=-fsanitize=address -fno-omit-frame-pointer -fno-common

ifeq (${CC},clang)
DEBUG_LDFLAGS=-fsanitize=address
else
DEBUG_LDFLAGS=-lasan
endif

endif

TARGET		:= ccownbd
OBJS		:= $(TARGET:=.o)

CC		:= gcc
CFLAGS		:= $(CFLAGS) $(DEBUG_FLAGS) -g -O3 -Wall -Wextra	\
		   -std=gnu99 -pthread -I../ccow/include -I../ccow/src/include
LDFLAGS		:= $(LDFLAGS) $(DEBUG_LDFLAGS) -pthread	-lccow -lccowutil

.PHONY: all clean

$(TARGET): %: %.o
	$(CC) -o $@ $< $(LDFLAGS)

$(TARGET:=.o): %.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(TARGET) $(OBJS)

install: $(TARGET)
	mkdir -p $(DESTDIR)$(SRCDIR)/sbin 2> /dev/null || true
	cp -a $(TARGET) $(DESTDIR)$(SRCDIR)/sbin

all: install

uninstall:
	rm -f $(DESTDIR)$(SRCDIR)/sbin/$(TARGET)
