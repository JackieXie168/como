#!/bin/sh
#
# $Id$
#
# Top level script to compile como.
#
# All arguments are passed directly to gmake.
# We suggest:
#	sh build.sh clean		# to clean the tree
#	sh build.sh -s			# to build things
#
case `uname` in
FreeBSD)
    MAKE=gmake
    ;;
*)	# Linux, CYGWIN*
    MAKE=make
    ;;
esac

mk=como.gmk	# The Makefile name
# We need to compile the libs first
for file in `find base modules man -name ${mk}`
do
	olddir=`pwd`
	cd `dirname $file`
	echo
	echo "--> Working in `pwd`"
	echo
	if ! $MAKE $@ -f ${mk}; then
		echo "*** Error in `pwd`:"
		echo "***        make -f ${mk} $@"
		exit
	fi
	cd $olddir
done
echo
echo "--> Success."
