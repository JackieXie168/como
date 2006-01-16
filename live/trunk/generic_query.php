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
    /*  Get Input Vars  */
    require_once("include/getinputvars.php.inc"); 

    $filename=$comonode . "_" . $module . "_" . $stime . "_" . 
	      $etime . ".html";

    /*  File caching check  */
    if ((file_exists("$RESULTS/$filename")) && ($USECACHE)) {
        $data = array();
        $data[0] = 1;
        $data[1] = file_get_contents("$RESULTS/$filename");

    /*  File doesn't exist or USECACHE is off, regen file  */
    } else {
	require_once ("class/query.class.php");
	$query = new Query($stime, $etime, $RESULTS, $GNUPLOT, 
			   $CONVERT, $RESOLUTION);
	$query_string = $query->get_query_string($module, $format, 
						 $http_query_string);
	$data = $query->do_query ($node->comonode, $query_string);

	/*  Write html out to a file so we dont have to query all the time */
        if ($data[0]){
	    $fullname = "{$query -> rootdir}/{$query->results_dir}/$filename";
	    $fh = fopen ($fullname, "w");
	    fwrite ($fh, $data[1]);
	    fclose ($fh);
        }
    }
 
    /*  Stream out the data to the iframe  */
    if (!$data[0]) {
	print "<p align=center>"; 
	print "Sorry but this module is not available <br>";
	print "on this node at the moment.<br>";
    #    exit; 
    } else {
	#$filename = $query->plot_query($data[1], $node->comonode, $module);
	print "$data[1]";

    }
?>
