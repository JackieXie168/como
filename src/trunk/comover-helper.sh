#!/bin/sh
SVNVERSION=`which svnversion 2> /dev/null`
[ $? -eq 0 ] && $SVNVERSION . 2> /dev/null && awk -F: '{print int($NF)}' 
