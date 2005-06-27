<!-- $Id$ --> 

<?php 

include("comolive.conf"); 
$host = $_GET['node'];

/* 
 * first of all, parse the input variables.
 * this file will give us the following variables: 
 *   . module name (mdl)
 *   . filter expression (filter)
 *   . start time (stime) aligned to $GRANULARITY (see comolive.conf)
 *   . end time (etime) aligned to $GRANULARITY (see comolive.conf)
 */ 
include ("include/variables.php"); 

/* 
 * set some internal variables 
 */
$rootdir = $_SERVER['DOCUMENT_ROOT'];
$basedir = $rootdir . dirname($_SERVER['PHP_SELF']);
$filename = "$RESULTS/$host" . "_" . $mdl . "_" . $stime . "_" . $etime;
$fullname = "$rootdir$filename"; 
$query = "module=$mdl&start=$stime&end=$etime&format=gnuplot";
if (!is_null($filter)) 
    $query = "$query&filter=$filter";
else 
    $query .= "&filter=ALL"; 

/* 
 * make sure the directory where the results should 
 * go exists. 
 */
$results_dir = $_SERVER['DOCUMENT_ROOT'] . $RESULTS; 
if (!(file_exists($results_dir))) {
    print "Please create the directory $results_dir"; 
    // system("mkdir -p $abs_path/results");
    // system("chmod 777 $abs_path/results");
    exit;
}

?>

<html>
  <title>CoMolive! - Intel Research Cambridge</title>
  <link rel="stylesheet" type="text/css" name="como" href="css/live.css">
  <link rel="shortcut icon" href="images/live_favicon.ico">
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
  <meta name="description" content="CoMolive!">
<body>

<?php 
/* 
 * check if we have cached the file. otherwise, generate the 
 * .eps and .jpg files. 
 */
$script = file_get_contents("http://$host/?$query"); 
if (!$script) { 
    print "Sorry. Function not supported at the moment.<br>\n";  
    print "</body></html>"; 
    exit; 
}

$num = substr_count($script, "\n");
$output = explode("\n", $script, $num);

?>

<table cellpadding=1>
  <tr> 
    <td colspan=5>Date</td> 
    <td width=200 align=center>IP /24 destination prefix</td> 
    <td width=150 align=center>Bytes</td>
    <td width=150 align=center>Packets</td>
  </tr>

<?php
for ($i = 1; $i < $num; $i++) {
    print "<tr>";
    $tok = strtok($output[$i], " ");
    while ($tok !== false) { 
	print "<td align=center>$tok</td>\n"; 
	$tok = strtok(" ");
    } 
    print "</tr>\n";
}
?>
</table>
</body></html>




