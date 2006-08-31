<!--  $Id$  -->
<?php 
/* 
 *  query.php
 * 
 *  query.php will contact a como node and return 
 *  an image.
 *
 *  query.php needs to be passed comonode=host:port 
 *  other options are module, filter, end, and  start 
 * 
 *  set some internal variables 
 */

/* 
 *  all timestamps are always aligned to the granularity 
 *  defined in the comolive.conf file. 
 */

class Query {
    var $start;
    var $end;
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
    var $fullname;

    /*  Constructor  */
    function Query ($start, $end, $G) {
        $results_dir = $G['RESULTS']; 
	$gp = $G['GNUPLOT']; 
	$con = $G['CONVERT'];
	$res = $G['RESOLUTION'];

        $this->GNUPLOT=$gp;
        $this->CONVERT=$con;
        $this->start=$start;
        $this->end=$end;

        /*  Set the Granularity  */
        $this->granularity = ($this->end - $this->start) / $res;

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
            if (!(("start" == $var[0]) || ("end" == $var[0]) || 
		  ("comonode" == $var[0]) || ("module" == $var[0]) ||
		  ("format" == $var[0]))) {
                $query .= "&" . $a[$i];
            }
        }
        if ($module != "netflow-anon") {
	   $this->query_string  = "module=$module&start=$this->start&end=$this->end&wait=$this->wait&format=$format&granularity=$this->granularity" . $query;
        } else {
	   $this->query_string  = "module=$module&start=$this->start&end=$this->end&wait=$this->wait&format=$format" . $query;
        }
        /*  This will urlencode the query_string  */
        $this->query_string = strtr ($this->query_string, " ", "+");
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

	$this->filename = "$comonode" . "_" . $module . "_" . $this->start . "_" . $this->end;
	$fullname = "$this->rootdir/$this->results_dir/$this->filename";

        /*  See if the plot is already there  */
        $image = $this->results_dir . "/" . $this->filename . ".jpg";
        if (!($this->plot_exists("$image"))) {
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

	    /* 
             *  Now invoke gnuplot and convert to generate the 
             * .eps and .jpg files 
             */
            if (!(file_exists($this -> GNUPLOT))) {
                print "Please review comolive.conf and check path to "; 
                print "gnuplot ({$this -> GNUPLOT})<br>";
                exit;
            }
            $convert = explode (" ", $this -> CONVERT);
            if (!(file_exists($convert[0]))) {
                print "Please review comolive.conf and check path to "; 
                print "convert ({$this -> CONVERT})<br>";
                exit;
            }

	    /* remove all shell commands from gnuplot script we receive */ 
	    system("sed -e \"s/\`//g\" -e \"s/\!//g\" $fullname.gp > $fullname.clngp", $return);

	    /* run the gnuplot command */ 
	    system("$this->GNUPLOT < $fullname.clngp > $fullname.eps", $return);

            /* if .eps file has filesize of 0, do not create jpg */
            if (filesize("$fullname.eps"))
		system("$this->CONVERT $fullname.eps $fullname.jpg", $return);

	    /* delete working files */ 
	    system("rm -f $fullname.gp", $return);
	    system("rm -f $fullname.clngp", $return);
	}
        $this->fullname = $fullname;
	return "$this->results_dir/$this->filename";
    }
    function getFullFilename () {
        return $this->fullname;
    }
}
?>
