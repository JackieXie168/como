<?php
/*  node.class.php
 *  $Id$ 
 *
 *  methods:
 *    PrintDebug()
 *    SetStarttime(stime)
 *    SetEndtime(etime)
 */

class Node {
    var $comonode;
    var $hostaddr;
    var $hostport;
    var $nodename;
    var $nodeplace;
    var $comment;
    var $linkspeed;
    var $version;
    var $builddate;
    var $start;
    var $curtime;
    var $modinfo;
    var $status;
    var $module;
    var $filter;
    var $stime;
    var $etime;
    var $timeperiod;
    var $timebound;
    /*  Some Globals  */
    var $G;
    var $NODEDB;

    /*  Constructor  */
    function Node($comonode, $G) {
        $this->NODEDB = $G['NODEDB'];
        $this->G = $G;

	$timeperiod = $G['TIMEPERIOD'];
	$timebound = $G['TIMEBOUND'];
    
        /*  Check to make sure there is a host and port number */
        $hostarray = split (":", $comonode);
        if ((count($hostarray)) == 2 && is_numeric ($hostarray[1])) {
	    $this -> comonode = $comonode;
	    $this -> hostaddr = $hostarray[0];
	    $this -> hostport = $hostarray[1];
	    $this -> timeperiod = $timeperiod;
	    $this -> timebound = $timebound;

            /*  Cache the status query so we don't have to query CoMo  */
            $this -> statusExists($comonode);

	    $query = file("http://$comonode/?status");

	} else {
            $query = FALSE;
        }
	if ($query == FALSE) {
            $this->status="FAIL";
	} else {
            $this->status="OK";
	    /* parse the node information */
	    for ($i=0;$i<count($query);$i++) {
              if ($query[$i] != "\n") {
		$lines = explode(" ", $query[$i],2);
		$args = explode("|", $lines[1]);
                $val = trim ($lines[0]); 
                switch ($val) {
                    case "Node:":
                        list ($this->nodename, $this->nodeplace, 
                              $this->linkspeed) = $args;
		    break;
		    case "Start:":
			$this->start = $args[0];
		    break;
		    case "Current:":
			$this->curtime = $args[0];
		    break;
		    case "Comment:":
			$this->comment= $args[0];
		    break;
                    case "Module:":
                        $str = urlencode(trim($args[1]));
                        $module = trim($args[0]);
                        $this->modinfo[$module]['filter'] = $str;
                        $this->modinfo[$module]['stime'] = trim($args[2]);
                        $this->modinfo[$module]['formats'] = trim($args[3]);
		    break;
                    case "--":
			$version = explode("(built:", $args[0]);
			$this->version = trim($version[0]);
                        /*  Can't get rid of damn rt para  */
                        $test = split (")", $version[1]);
			$this->builddate = trim($test[0]);
		    break;
                }
	      }
	    } 

            /*
	     *  Set the end time of the query to the current como time.
	     */
	    $etime = $this->curtime;

	    /*
	     *  get the start time. if not defined, we use
	     *  the default value TIMEPERIOD defined in comolive.conf
	     */
	    $stime = $etime - $this->timeperiod;

            /*  Make sure start time is not before the module start time  */
            if ($stime < $this -> modinfo[$module]['stime'])
                $stime = $this -> modinfo[$module]['stime'];

	    /*
	     *  all timestamps are always aligned to the timebound
	     *  defined in the comolive.conf file.
	     */
	    $stime -= $stime % $this->timebound;
	    $etime -= $etime % $this->timebound;

            $this->stime = $stime;
            $this->etime = $etime;
	}
    }
    function statusExists ($comonode) {
        $statuslife = "600";
        $absroot = $this -> G['ABSROOT'];
        $results = trim ($this->G['RESULTS'], "./");
        $timenow = time();
        /*  Get the current status file  */
        $dh = opendir ("$absroot/$results");
	$needlefile = $comonode . "_status_";
	while (false!==($filez= readdir($dh))) {
	    if ($filez!= "." && $filez!= ".." 
                && strstr ($filez, "$needlefile")) {
		$statusfile = $filez;
	    }
	}
        if (isset($statusfile)) {
	    $tmpvar = split ("_", $statusfile);
	    $curstatustime = $tmpvar[2];
	    if (($timenow - $curstatustime) > $statuslife) {
		$returnstatus = 0;
                $statusfilename = "$absroot/$results/$statusfile";
                system ("rm -f $statusfilename");
	    } else {
		$returnstatus = 1;
	    }
        } else 
	    $returnstatus = 0;

        return ($returnstatus);
    }
    
    function removeFile ($filename) {
        $absroot = $this -> G['ABSROOT'];
        $results = trim ($this->G['RESULTS'], "./");
	$dafilename = "$absroot/$results/$filename";
	system ("rm -f $dafilename");
    }

    function PrintDebug() {
	print "<br>DEBUGING INFO<BR>";
        print "nodename: $this->nodename<br>";
        print "nodeplace: $this->nodeplace<br>";
	print "comment: $this->comment<br>";
	print "linkspeed: $this->linkspeed<br>";
	print "version: $this->version<br>";
	print "builddate: $this->builddate<br>";
	print "firstpacket: $this->firstpacket<br>";
	print "lastpacket: $this->lastpacket<br>";

    }
    function SetStarttime ($stime) {
        $this->stime = $stime;
    }
    function SetEndtime ($etime) {
        $this->etime = $etime;
    }
    function CheckFirstPacket ($stime,$mod) {
        if ($stime < $this->modinfo[$mod]['stime']){
            $this->stime = $this->modinfo[$mod]['stime'];
        } else {
            $this->stime = $stime;
        }
        return $this->stime;
    }
    /*  Return a list of modules that support different features  
     *  needle may be gnuplot, html, etc.  This info is captured
     *  on a per module basis.  
     */
    function GetModules ($needle) {
        $keys = array_keys($this -> modinfo);
        $modules = array();
        for ($i=0;$i<count($keys); $i++) {
            $haystack = $this -> modinfo[$keys[$i]]['formats'];
            if (strstr($haystack, $needle)) {
                array_push ($modules, $keys[$i]);
            }
        }
        return ($modules);
    }
    /*  Return an array with the modules that a user
     *  has chosen that are saved in a config file.  
     *  Appropriate values for value are
     *  "main" for the main window  and "secondary"
     *  for the right hand queries
     */
    function GetConfigModules ($comonode, $value) {
        $NODEDB = $this -> NODEDB;
        if ($value == "main")
	    $needle = "main_mods";
        if ($value == "secondary")
	    $needle = "sec_mods";

	if (file_exists("$NODEDB/$comonode.conf")){
	    $dafile = file ("$NODEDB/$comonode.conf");
	    for ($i=0;$i<count($dafile);$i++){
		if (strstr($dafile[$i], $needle)) {
		    $tmp = $dafile[$i];
		}
	    }
            $val = explode (";;", $tmp);

            /*  Trim out the new line  */
            for ($i=0;$i<count($val);$i++) 
                $val[$i] = trim($val[$i]);

            return ($val);
            
	} else {
	    /*  Create a default file  */
            $usable_mods = $this -> GetModules("gnuplot");
	    $val = "main_mods";
            for ($i=0;$i<count($usable_mods);$i++) {
                $val = $val . ";;"; 
                $val = $val . $usable_mods[$i];
            }
	    $val = $val . "\n"; 
	    $val = $val . "sec_mods;;alert;;topdest;;topports\n";
	    $fh = fopen ("$NODEDB/$comonode.conf", "w");
	    fwrite ($fh, $val);
            /*  Re-call this function  */
            return ($this -> GetConfigModules($comonode, $NODEDB, $value));
	}
    }

}
?>
