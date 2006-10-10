#
# $Id$
#
# A convenience Makefile for como that creates a build directory
# and calls CMake to produce the real Makefiles

BUILD_TYPE?=debug

.PHONY: all install clean distclean $(BUILD_TYPE)/Makefile

all: $(BUILD_TYPE)/Makefile
	cd $(BUILD_TYPE) && make all

$(BUILD_TYPE):
	mkdir -p $(BUILD_TYPE)

$(BUILD_TYPE)/Makefile: $(BUILD_TYPE)
	cd $(BUILD_TYPE) && cmake .. -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) $(MAKEFLAGS)

install: $(BUILD_TYPE)/Makefile
	cd $(BUILD_TYPE) && make install

clean: $(BUILD_TYPE)/Makefile
	cd $(BUILD_TYPE) && make clean

distclean:
	rm -rf $(BUILD_TYPE)
