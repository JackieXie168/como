#!/bin/sh

usage () {
    echo "usage: $0 <tpl> <name> <type> <field>";
    echo "<tpl> template file";
    echo "<name> name to be assigned to the tpl instance";
    echo "<type> type to be used in the tpl instance";
    echo "<field> field of type to be used by the tpl instance";
    exit 1;
}

if [ $# -lt 4 ];then
    usage;
fi

tpl=$1
name=$2
type=$3
field=$4

echo "/* File automatically generated from $tpl. Do not modify! */" > $name.h
cat $tpl | sed -e "s/<field>/$field/g" -e "s/<type>/$type/g" -e "s/<name>/$name/g" >> $name.h
echo "mktype: type $name created as instance of $tpl in $name.h"
exit 0

