<?php

# GET input variables
#
if (isset($_GET['module']) && ($_GET['module'] != ""))
    $mdl = $_GET['module'];
else
    $mdl = "counter"; 

if (isset($_GET['filter']) && ($_GET['filter'] != ""))
    $filter = $_GET['filter'];
else
    $filter = NULL; 

/*  
 * get the end time of the query, if it is not defined 
 * we use the current time instead (compensating for the delay
 * from real time). 
 */
if (isset($_GET['etime']) && ($_GET['etime'] != "")) {
    $etime = $_GET['etime'];
} else {
    $etime = gettimeofday();	
    $etime = $etime["sec"] - $delay; 
}

/* 
 * get the start time. if not defined, we use 
 * the default value TIMEPERIOD defined in comolive.conf
 */
if(isset($_GET['stime']) && ($_GET['stime'] != ""))
    $stime = $_GET['stime'];
else
    $stime = $etime - $TIMEPERIOD;
    
/* 
 * all timestamps are always aligned to the granularity 
 * defined in the comolive.conf file. 
 */
$stime -= $stime % $GRANULARITY; 
$etime -= $etime % $GRANULARITY; 

?>
