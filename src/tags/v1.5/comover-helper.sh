#!/bin/sh
SVNVERSION=`which svnversion 2> /dev/null`
if [ $? -eq 0 ]; then
  svnver=`$SVNVERSION . 2> /dev/null`
  [ $? -eq 0 ] && echo "$svnver" | awk -F: '{print int($NF)}'
fi
