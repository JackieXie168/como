#
# $Id$
#
# A convenience Makefile for como that creates a build directory
# and calls CMake to produce the real Makefiles

BUILD_TYPE?=debug

.PHONY: all install clean cmake distclean modules modules-install

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
	rm -rf {release,debug,debugfull,custom,ls}


modules:
	mkdir -p $(BUILD_TYPE)/modules
	modules/build_modules.sh $(BUILD_TYPE) build

modules-install:
	mkdir -p $(BUILD_TYPE)/modules
	modules/build_modules.sh $(BUILD_TYPE) install

# wrappers to the two most used build types
release: BUILD_TYPE:=release
release: all
release-install: BUILD_TYPE:=release
release-install: install
release-modules: BUILD_TYPE:=release
release-modules: modules
release-modules-install: BUILD_TYPE:=release
release-modules-install: modules-install

debug: BUILD_TYPE:=debug
debug: all
debug-install: BUILD_TYPE:=debug
debug-install: install
debug-modules: BUILD_TYPE:=debug
debug-modules: modules
debug-modules-install: BUILD_TYPE:=debug
debug-modules-install: modules-install

# wrappers for load shedding build type
ls: BUILD_TYPE:=ls
ls: all
ls-install: BUILD_TYPE:=ls
ls-install: install
ls-modules: BUILD_TYPE:=ls
ls-modules: modules
ls-modules-install: BUILD_TYPE:=ls
ls-modules-install: modules-install

