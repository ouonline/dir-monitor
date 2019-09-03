CC := gcc
AR := ar

ifeq ($(debug), y)
    CFLAGS := -g
else
    CFLAGS := -O2 -DNDEBUG
endif
CFLAGS := $(CFLAGS) -Wall -Werror -Wextra -fPIC

ifndef DEPSDIR
    DEPSDIR := $(shell pwd)/..
endif

MODULE_NAME := dirmonitor

INCLUDE := -I$(DEPSDIR)
LIBS := -lpthread

OBJS := $(patsubst %.c, %.o, $(wildcard *.c))

TARGET := lib$(MODULE_NAME).a lib$(MODULE_NAME).so

.PHONY: all clean pre-process

all: $(TARGET)

$(OBJS): | pre-process

pre-process:
	d=$(DEPSDIR)/utils; if ! [ -d $$d ]; then git clone https://github.com/ouonline/utils.git $$d; fi

lib$(MODULE_NAME).a: $(OBJS)
	$(AR) rc $@ $^

lib$(MODULE_NAME).so: $(OBJS)
	$(CC) -shared -o $@ $^ $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)
