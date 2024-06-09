CC := gcc
CFLAGS := -Wall -Wextra -std=c99 -g -ggdb2 -pedantic -Wpedantic
DEFINES :=
LIBS := -lpthread

ifeq ($(BUILD_TYPE), RELEASE)
CFLAGS := -Wall -Wextra -std=c99 -O3 -pedantic -Wpedantic
endif

SRCDIR := src
BUILDDIR := build

SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS))

BINARYNAME := schwatz
BINARY := $(BUILDDIR)/$(BINARYNAME)

.PHONY: all clean run

all: always $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(CFLAGS) $< -o $(BINARY) $(LIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(DEFINES) -c $< -o $@

always:
	mkdir -p $(BUILDDIR)

clean:
	rm -rf $(BUILDDIR)

run:
	./$(BINARY)
