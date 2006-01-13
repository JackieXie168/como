#!/bin/sh

##  Richard Gass <richard.gass@intel.com>
##  20060113

##  This script should be run by cron every 5 mins.  It will 
##  use wget or fetch to force a load of the latest pages so 
##  the images will be cached.

##  Time period
TIMEPERIOD=$((6*3600));

##  Modules to cache
modules="traffic application protocol utilization"

##  Linux uses wget FreeBSD uses fetch
HTTPGET="/usr/bin/wget -p -q -O"
#HTTPGET="/usr/bin/fetch -q -o"
WEBROOT="~rgass/como"
ABSPATH="/home/rgass/public_html/como"

sec=$(date +%s)
tmp=$(expr $sec % 300)
etime=$(expr $sec - $tmp)
stime=$(($etime-$TIMEPERIOD))

##  Do not change anything beyond this point
##  unless you know what you are doing
BASEDIR=$(dirname $0)
dbfile="$ABSPATH/db/nodes.lst";
nodes=$(cat $dbfile  | grep -v "CoMo Name" | awk -F ";;" '{print $2}')

for comonode in $nodes;do
    host=$(echo $comonode | awk -F":" '{print $1}')
    for mod in $modules;do
        filter=$($HTTPGET - http://$comonode/?status | grep $mod | cut -d: -f3 | sed "s/ //" | sed "s/ /%20/g")
        $HTTPGET test http://$host/$WEBROOT/dashboard.php?comonode=$comonode\&module=$mod\&filter=$filter 
    done
done
