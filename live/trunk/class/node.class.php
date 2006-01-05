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
    var $loadedmodule;
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
                    $this->loadedmodule[$module] = $filter;
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
    function CheckFirstPacket ($stime) {
        if ($stime < $this->start){
            $this->stime = $this->start;
        } else {
            $this->stime = $stime;
        }
        return $this->stime;
    }
}
?>
