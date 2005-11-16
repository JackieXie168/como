<!-- $Id$ --> 

<?php 

/* 
 * set some internal variables 
 */
$rootdir = $_SERVER['DOCUMENT_ROOT'];
$basedir = $rootdir . dirname($_SERVER['PHP_SELF']);
$filename = "$RESULTS/$host" . "_" . $mdl . "_" . $stime . "_" . $etime;
$fullname = "$rootdir$filename"; 

$query = "module=$mdl&start=$stime&end=$etime&format=gnuplot&wait=no";

$granularity = ($etime - $stime) / 100; 
$query .= "&granularity=$granularity";

if (!is_null($filter)) 
    $query = "$query&filter=$filter";
else 
    $query .= "&filter=all"; 

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

/* 
 * check if we have cached the file. otherwise, generate the 
 * .eps and .jpg files. 
 */
if (!file_exists("$fullname.jpg")) { 
    $script = file_get_contents("http://$host/?$query"); 
    if (!$script) { 
	print "<p align=center>"; 
	print "Sorry but this module is not available <br>";
	print "on this node at the moment.<br>"; 
	
    } else {  
	/*
	 * in order to plot correctly, we need to replicate the data
	 * we have received from the CoMo node (in $script) a number of
	 * times equal to the number of lines in the graph. We do so by
	 * skipping the first line (that is assumed to contain all the
	 * gnuplot commands) and replicating the other lines a number of
	 * times equal to the number of times the string '"-"' appears.
	 */
	$output = explode("\n", $script, 2);

	/* Find number of "-" in gnuplot query to append data x times */
	$num = substr_count($output[0], '"-"');

	$fh = fopen("$fullname.gp", "w");
	if (!$fh) {
	    print "Could not open file $fullname<br>";
	    exit(0);
	}

	fwrite($fh, $script);
	while (--$num > 0)
	    fwrite($fh, $output[1]);
	fclose($fh);

	/* now invoke gnuplot and convert to generate the .eps and .jpg files */
	system("sed \"s/\`//g\" $fullname.gp > $fullname.cleangp", $return);
	system("$GNUPLOT < $fullname.cleangp > $fullname.eps", $return);
	system("$CONVERT $fullname.eps $fullname.jpg", $return);
    //    system("rm -f $fullname.gp", $return);

    }
}

if (file_exists("$fullname.jpg")) { 
    if ($USEFLASH == false)
	print "<img src=$filename.jpg>";
    else
	include("flash/zooming.php");
}

?>




