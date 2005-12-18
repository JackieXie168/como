<?php
require_once("comolive.conf");
require_once("class/node.class.php");

/*  get the node hostname and port number */
/*  This is not in the include file because it needs to be called 
 *  before the getinputvars.php.inc file is called (Chicken/egg)
 */

if (isset($_GET['comonode'])){
    $comonode = $_GET['comonode'];
}else{
    print "This file requires the comonode=host:port arg passed to it<br>";
    print "Thanks for playing!<br><br><br><br><br><br><br>";
    include("include/footer.php.inc");
    exit;
}


$node = new Node ("$comonode", $TIMEPERIOD, $TIMEBOUND);

require_once("include/getinputvars.php.inc"); 

/*  Get Input Vars  */
/*include("include/getinputvars.php.inc");*/

require_once ("class/query.class.php");

$query = new Query($stime, $etime, $RESULTS, $GNUPLOT, $CONVERT, $RESOLUTION);
$query_string = $query->get_query_string($module, $format, $http_query_string);
$data = $query->do_query ($node->comonode, $query_string);
if (!$data[0]) {
/*
    print "<p align=center>"; 
    print "Sorry but this module is not available <br>";
    print "on this node at the moment.<br>";
*/
    exit; 
}

#$filename = $query->plot_query($data[1], $node->comonode, $module);

print "$data[1]";
?>
