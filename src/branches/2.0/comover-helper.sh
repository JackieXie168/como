#!/bin/sh
SVNVERSION=`which svnversion 2> /dev/null`
[ $? -eq 0 ] && $SVNVERSION . | awk -F: '{print int($NF)}' 
