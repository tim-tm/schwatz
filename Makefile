NPROCS=$(shell nproc)
MKFLAGS=-j$(NPROCS)

all:
	make -C schwatz-server $(MKFLAGS)
	make -C schwatz $(MKFLAGS)

clean:
	make -C schwatz-server clean
	make -C schwatz clean
