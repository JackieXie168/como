#
# $Id$
#
# A convenience Makefile for como that creates a build directory
# and calls CMake to produce the real Makefiles

BUILD_TYPE?=debug

.PHONY: all install clean cmake distclean

all: cmake
	cd $(BUILD_TYPE) && make all

install: cmake
	cd $(BUILD_TYPE) && make install

clean: cmake
	cd $(BUILD_TYPE) && make clean

cmake:
	which cmake || (echo; echo "CoMo depends on CMake \
 (http://www.cmake.org) to build. Please install CMake first."; echo)
	mkdir -p $(BUILD_TYPE)
	cd $(BUILD_TYPE) && \
	    cmake .. -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) $(MAKEFLAGS)

distclean:
	rm -rf {release,debug,debugfull,custom}

# wrappers to the two most used build types
release: BUILD_TYPE:=release
release: all
release-install: BUILD_TYPE:=release
release-install: install

debug: BUILD_TYPE:=debug
debug: all
debug-install: BUILD_TYPE:=debug
debug-install: install

