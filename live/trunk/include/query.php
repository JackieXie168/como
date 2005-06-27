<!-- $Id$ --> 

<?php 

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

/* 
 * check if we have cached the file. otherwise, generate the 
 * .eps and .jpg files. 
 */
if (!file_exists("$fullname.jpg")) { 
    $script = file_get_contents("http://$host/?$query"); 
    if (!$script) 
	exit; 

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
    system("$GNUPLOT < $fullname.gp > $fullname.eps", $return);
    system("$CONVERT $fullname.eps $fullname.jpg", $return);
//    system("rm -f $fullname.gp", $return);
}

/* 
 * finally write the php_env.php file for the flash client 
 * 
 * XXX we have just one environment file. when multiple clients 
 *     are accessing the web page they may incur in conflicts over 
 *     this file and load the wrong images. probably adding session 
 *     information we can solve this problem. it is still not clear 
 *     how to inform the flash client about which file it needs to load. 
 */

$fp = fopen("$rootdir/$RESULTS/php_env.php", 'w');
$info = "image=$filename.jpg&node=$host&module=$mdl&start=$stime&end=$etime&format=gnuplot";
if (!is_null($filter))
    $info .= "&filter=$filter"; 
else
    $info .= "&filter=ALL";
fwrite($fp, "<?php echo \"$info\" ?>"); 
fclose($fp);


?>




