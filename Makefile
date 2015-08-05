CC := gcc

ifeq ($(debug), y)
    CFLAGS := -g
else
    CFLAGS := -O2 -DNDEBUG
endif

CFLAGS := $(CFLAGS) -Wall -Werror

INCLUDE :=
LIBS := -lpthread

SRC := $(wildcard *.c)
OBJS := $(patsubst %.c, %.o, $(SRC))
DEF := $(patsubst %.c, %.d, $(SRC))

TARGET := test_dir_monitor

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

sinclude $(DEF)
%.d:%.c
	@set -e; rm -f $@; \
	    $(CC) -MM $(INCLUDE) $< > $@.$$$$; \
	    sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	    rm -f $@.$$$$

clean:
	rm -f $(OBJS) $(DEF) $(TARGET) *.d.*
