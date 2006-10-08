<?php
    require_once ("../comolive.conf");
    require_once ("../class/node.class.php");
    require_once ("../class/query.class.php");
    require_once ("../include/framing.php");
    require_once ("../include/getinputvars.php.inc");

    /*  get the node hostname and port number */
    if (!isset($_GET['comonode'])) { 
        print "This file requires the comonode=host:port arg passed to it<br>";
        print "Thanks for playing!<br><br><br><br><br><br><br>";
        include("../include/footer.php.inc");
        exit;
    }

    $comonode = $_GET['comonode'];

    /*  Get any extras in the url;  Currently to grab blinc stuff  */
    if (isset($_GET['extra']))
        $extra = $_GET['extra'];
    else
        $extra = "";

    $G = init_global();
    $node = new Node ("$comonode", $G);

    /*  Get Input Vars  */
    $input_vars = init_env($node);
    $module = $input_vars['module'];
    $fiter = $input_vars['filter'];
    $end = $input_vars['end'];
    $start = $input_vars['start'];
    $format = $input_vars['format'];

    $http_query_string = $_SERVER['QUERY_STRING']; 

    $varname = "topn" . $module; 
    if (isset($_POST[$varname])) {
        $items = $_POST[$varname]; 
        setcookie($varname, $items);
        $http_query_string = ereg_replace("topn=[0-9]*", "topn=$items", $http_query_string);
    } 

    /*  This we catch if ip=addr is passed back from the
     *  module.  If it is, rewrite the filter to include
     *  the ip address that is returned
     */
    if (isset($input_vars['ip'])) {
        $var = explode ("&", $http_query_string); 
        $http_query_string = "";
        for ($i = 0; $i < count($var); $i++) {
            if (strstr($var[$i],"filter=")) {
                $tmp_filter = explode ("=", $var[$i]);
            } else if (strstr($var[$i], "ip=")) {
                $tmp_ip = explode ("=", $var[$i]);
                /*  This will need to be removed once CoMo returns
                 *  the ip without the mask
                 */
                $x  = explode ("/", $tmp_ip[1]);
                $daip = $x[0];
            } else {
                $http_query_string = $http_query_string . $var[$i];
                $http_query_string = $http_query_string . "&";
            }
        }
        $http_query_string = $http_query_string . "&filter=";
        $http_query_string = $http_query_string . $tmp_filter[1] ;
        /*  Not sure why I had "and dst" here so we will just 
            comment to make sure nothing breaks
         */
        #$http_query_string = $http_query_string . " and dst ";
        $http_query_string = $http_query_string . "dst ";
        $http_query_string = $http_query_string . $daip;
    } else {
        $daip="none";
    }

    $filename = md5($http_query_string) . "." . $format; 

    /*  File caching check  */
    if ((file_exists($G['RESULTS']. "/" . $filename)) && ($G['USECACHE'])) {
        $data = array();
        $data[0] = 1;
        $data[1] = file_get_contents($G['RESULTS'] . "/" . $filename);
    } else {
	/*  File doesn't exist or USECACHE is off, regen file  */

        /*  If USEBLINC is not set, then just print out the html formatted
         *  text that CoMo will return
         */
        if ($extra == "blincview" && !$G['USEBLINCVIEW']) {
            $format = "html";
        }
        $query = new Query($start, $end, $G);
        $query_string = $query->get_query_string($module, $format,
                                                 $http_query_string);
        $data = $query->do_query ($comonode, $query_string);
        /*  Write html out to a file so we dont have to query all the time */
        if (($data[0]) && ($G['USECACHE'])){
            $fullname = "{$query->rootdir}/{$query->results_dir}/$filename";
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
	/*  Blinc Code  */
	if (($extra == "blincview") && ($G['USEBLINCVIEW'])) {
	    $BRESULTS = $G['ABSROOT'] . "/" . $G['RESULTS'];
	    $blincfile = $comonode . 
			 "_" . $extra . "_" . $start . "_" .
			 $end . "_" . $daip . ".blinc";
	    $absblincfile = $BRESULTS . "/" . $blincfile;
            /*  Is there a blinc png file?  */
	    if ((!(file_exists("$absblincfile.png"))) || (!($G['USECACHE']))) {
		$fp = fopen ("$absblincfile.dat", "w");
		fwrite ($fp, $data[1]);
		fclose ($fp);
		$BLINCVIEWCMD = $G['BLINCVIEWCMD'];
		$DOT = $G['DOT'];
		system("$BLINCVIEWCMD $DOT $absblincfile < $absblincfile.dat", $return);
		system("rm -f $absblincfile");
            }
#		system("CONVERT $absblincfile.png1 $absblincfile.png", $return);

	    /*  This will take there request uri information and 
	     *  change the format back to html and remove blincview 
	     *  out of the url so we can relink back to the data
	     */
	    $relinker = $_SERVER["REQUEST_URI"];
	    $relinker = preg_replace ("/format=plain/i", 
				      "format=html", $relinker);
	    $relinker = preg_replace ("/extra=blincview/i", 
				      "", $relinker);
	    print "<center><table><tr><td colspan=2 align=center>";
	    print "<font size=6>Blinc View</font></td><td></tr>";
	    print "<tr><td colspan=2>";
	    print "<a href={$G['RESULTS']}/$blincfile.png>";
	    print "<img width=800 ";
	    print "src={$G['RESULTS']}/$blincfile.png>";
	    print "</a>";
	    print "</td></tr>";
	    print "<tr><td align=center><a href={$G['RESULTS']}/$blincfile.png>";
	    print "Download Image</a></td>";
	    print "<td><a href=$relinker>Text Output</a><td>";

	    print "</tr></table></center>";
	    exit;
	}
	print "$data[1]";
    }
?>

