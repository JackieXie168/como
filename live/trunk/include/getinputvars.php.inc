<!--  $Id$ -->
<!--  The following variables are set with this file
      . modules
      . filter
      . stime and etime (require node to be instantiated)
      . format
      . ip
      . http_query_string
-->
<?
/*  getinputvars.php.inc
 *
 */
#
# GET input variables
#
if (isset($_GET['module']) && ($_GET['module'] != ""))
    $module = $_GET['module'];
else
    $module = "traffic";

if (isset($_GET['filter']) && ($_GET['filter'] != ""))
    $filter = $_GET['filter'];
else
    $filter = "all";

if (isset($_GET['etime']) && ($_GET['etime'] != "")){
    $etime = $_GET['etime'];
    if (isset($node)){
	$node->SetEndtime($etime);
    }
} else
    $etime = $node->etime;

if(isset($_GET['stime']) && ($_GET['stime'] != "")){
    $stime = $_GET['stime'];
    if (isset($node)){
	$stime = $node->CheckFirstPacket($stime,$module);
	$node->SetStarttime($stime);
    }
} else
    $stime = $node->stime;

if(isset($_GET['format']) && ($_GET['format'] != ""))
    $format = $_GET['format'];
else
    $format = "gnuplot";

if(isset($_GET['ip']) && ($_GET['ip'] != ""))
    $ip = $_GET['ip'];

$http_query_string = $_SERVER['QUERY_STRING'];

?>
