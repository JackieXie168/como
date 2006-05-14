#
# $Id$
#
# Makefile for como. Actually, this is a fake Makefile.
# See como.gmk and build.sh for information about the
# actual build system.

.PHONY: clean all

varfile=config_vars
varfile_default=$(varfile).default
varfile_local=$(varfile).local

all:	$(varfile_local)
	sh ./build.sh -f `pwd`/$(varfile_local) $(.MAKEFLAGS) all

install:
	sh ./build.sh -f `pwd`/$(varfile_local) $(.MAKEFLAGS) install

clean:  $(varfile_local)
	sh ./build.sh -f `pwd`/$(varfile_local) clean

dist-clean: clean
	rm -f $(varfile_local)

$(varfile_local):
	cp $(varfile_default) $(varfile_local)
