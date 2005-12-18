<!--  $Id$  -->
<?php 
/* 
 *  query.php
 * 
 *  query.php will contact a como node and return 
 *  an image.
 *
 *  query.php needs to be passed comonode=host:port 
 *  other options are module, filter, etime, and  stime 
 * 
 *  set some internal variables 
 */

/* 
 *  all timestamps are always aligned to the granularity 
 *  defined in the comolive.conf file. 
 */

class Query {
    var $stime;
    var $etime;
    var $filter = "all";
    var $query_string;
    var $format;
    var $wait = "no";
    var $webroot;
    var $rootdir;
    var $filename;
    var $GNUPLOT;
    var $CONVERT;
    var $granularity;

    /*  Constructor  */
    function Query ($stime, $etime, $results_dir, $gp, $con, $res) { 
        $this->GNUPLOT=$gp;
        $this->CONVERT=$con;
        $this->stime=$stime;
        $this->etime=$etime;

        /*  Set the Granularity  */
        $this->granularity = ($this->etime - $this->stime) / $res;

        /*
         * Check directories and make sure they exist and are writable
         */
	$this->rootdir = dirname($_SERVER['SCRIPT_FILENAME']); 
	$this->results_dir = $results_dir;

	/* XXX still need to check if they exists and are writeable... */
    }

    function get_query_string ($module, $format, $args) {
       $query="";

	/* parse the args information */
        $a = explode("&", $args);
        for ($i=0; $i<count($a);$i++){
            $var = explode("=", $a[$i]);
            if (!(("stime" === $var[0]) || ("etime" === $var[0]) || 
		  ("comonode" === $var[0]) || ("module" === $var[0]) ||
		  ("format" === $var[0]))) {
                $query .= "&" . $a[$i];
            }
        }
        
       $this->query_string  = "module=$module&start=$this->stime&end=$this->etime&wait=$this->wait&format=$format&granularity=$this->granularity" . $query;
        return $this->query_string;
    }

    function do_query ($comonode, $query_string) {
        $r = array(0=> 0,1=>0);
	$script = file_get_contents("http://$comonode/?$query_string");
	if (!$script) {
            $r[0] = 0;
            return $r;
        } else {
            $r[0] = 1;
            $r[1] = $script;
        }
        return $r;
    }

    function plot_exists($filename) {
        if (file_exists("$filename")){
            return 1;
        } else {
            return 0;
        }
    }
    function plot_query($query_output, $comonode, $module) {

	$this->filename = "$comonode" . "_" . $module . "_" . $this->stime . "_" . $this->etime;
	$fullname = "$this->rootdir/$this->results_dir/$this->filename";

        /*  See if the plot is already there  */
        $image = $this->results_dir . "/" . $this->filename . ".jpg";
        if (!($this->plot_exists("$image"))){
	    /*
	     * in order to plot correctly, we need to replicate the data
	     * we have received from the CoMo node (in $query_output) a number 
	     * of times equal to the number of lines in the graph. We do so by
	     * skipping the first line (that is assumed to contain all the
	     * gnuplot commands) and replicating the other lines a number of
	     * times equal to the number of times the string '"-"' appears.
	     */
	    $output = explode("\n", $query_output, 2);

	    /* Find number of "-" in gnuplot query to append data x times */
	    $num = substr_count($output[0], '"-"');
	    $fh = fopen("$fullname.gp", "w");
	    if (!$fh) {
		print "Could not open file $fullname<br>";
		exit(0);
	    }

	    fwrite($fh, $query_output);
	    while (--$num > 0)
		fwrite($fh, $output[1]);
	    fclose($fh);

	    /* now invoke gnuplot and convert to generate the .eps and .jpg files */
	    system("sed \"s/\`//g\" $fullname.gp > $fullname.cleangp", $return);
	    system("$this->GNUPLOT < $fullname.cleangp > $fullname.eps", $return);
	    system("$this->CONVERT $fullname.eps $fullname.jpg", $return);
	//    system("rm -f $fullname.gp", $return);

	}
        $this->fullname = $fullname;
	return "$this->results_dir/$this->filename";
    }
    function getFullFilename () {
        return $this->fullname;
    }
}
?>
