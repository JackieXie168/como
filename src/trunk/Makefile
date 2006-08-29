#
# $Id$
#
# A convenience Makefile for como that creates a build directory
# and calls CMake to produce the real Makefiles

.PHONY: all install clean distclean

all: build/Makefile
	cd build && make all

build:
	if [ ! -d build ]; then mkdir build; fi

cmake: build
	cd build && cmake .. $(MAKEFLAGS)

build/Makefile: cmake

install: build/Makefile
	cd build && make install

clean: build/Makefile
	cd build && make clean

distclean:
	rm -rf build
