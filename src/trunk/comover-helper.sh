#!/bin/sh
SVNVERSION=`which svnversion 2> /dev/null`
[ $? -eq 0 ] && $SVNVERSION | sed 's/M//' | sed 's/S//' | sed 's/^[0-9]\+://'
