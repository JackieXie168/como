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

    /*  Constructor  */
    function Node($host, $timeperiod, $timebound) {
        $this->comonode = $host;
        $this->timeperiod = $timeperiod;
        $this->timebound = $timebound;

	$query = file_get_contents("http://$host/?status");
	if ($query == FALSE) {
            $this->status="FAIL";
	} else {
            $this->status="OK";
	    /* parse the node information */
	    $tok = strtok($query, ":\n");
	    while ($tok !== FALSE) {
		if ($tok === "Name")
		    $this->nodename = strtok(":\n");
		else if ($tok === "Location")
		    $this->nodeplace = strtok(":\n");
		else if ($tok === "Comment")
		    $this->comment = strtok(":\n");
		else if ($tok === "Speed")
		    $this->linkspeed = strtok(":\n");
		else if ($tok === "Version")
		    $this->version = strtok(":\n");
		else if ($tok === "Build date")
		    $this->builddate = strtok(":\n");
		else if ($tok === "Current")
		    $this->curtime = ((int) strtok(":\n"));
		else if ($tok === "Start")
		    $this->start = ((int) strtok(":\n"));
		else if ($tok === "Module"){
		    $module = trim(strtok(":\n\t"));
		    strtok(":\n\t");
		    $filter = trim(strtok(":\n\t"));
                    /*  Replace spaces with %20  */ 
                    $str = preg_replace ('/ /', '%20', $filter);
                    $this->modinfo[$module]['filter'] = $str;
		    strtok(":\n\t");
		    $str = trim(strtok(":\n\t"));
                    $this->modinfo[$module]['formats'] = $str;
		    strtok(":\n\t");
		    $str = trim(strtok(":\n\t"));
                    $this->modinfo[$module]['stime'] = $str;
		}
		$tok = strtok(":\n");
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
    function GetConfigModules ($comonode, $NODEDB, $value) {
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
	    $val = "main_mods;;traffic;;application;;protocol;;utilization\n";
	    $val = $val . "sec_mods;;alert;;topdest;;topports\n";
	    $fh = fopen ("$NODEDB/$comonode.conf", "w");
	    fwrite ($fh, $val);
            /*  Re-call this function  */
            return ($this -> GetConfigModules($comonode, $NODEDB, $value));
	}
    }

}
?>
