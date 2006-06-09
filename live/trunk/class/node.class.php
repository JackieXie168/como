<!-- $Id$  -->

<?php

class Node {
    var $status; 		/* TRUE if initialization succeded */
    var $hostaddr;		/* CoMo node IP address (or name) */
    var $hostport;		/* CoMo node port number */
    var $db_path;		/* Path to the CoMolive! DB */
    var $results;		/* Path to the CoMolive! results directory */

    var $nodename; 		/* Information derived from ?status query */ 
    var $nodeplace;	
    var $comment;
    var $linkspeed;
    var $version;
    var $builddate;
    var $start;
    var $curtime;
    var $modinfo;
    var $module;
    var $filter;
 
    var $stime; 		/* query start and end time */ 
    var $etime; 		/* XXX unclear why we need to keep it here */

    /* 
     * constructor for the class. 
     * this will run a ?status query (unless it is already cached) 
     * and store all informations about the node and the modules
     * that are currently running. 
     */
    function Node($comonode, $G) {
	$this->status = TRUE; 
        $this->db_path = $G['ABSROOT'] . "/" . $G['NODEDB'];
	$this->results = $G['ABSROOT'] . "/" . $G['RESULTS'];

	/* 
         * the comonode may consist of host:port or just port. if 
         * it is just the port number, we assume host is equal to 
         * localhost
         */
        $hostarray = split (":", $comonode);
        $this->hostaddr = (count($hostarray) > 1)? $hostarray[0] : "localhost";
        $this->hostport = (count($hostarray) > 1)? $hostarray[1] : $hostarray; 

	if (!is_numeric($this->hostport)) {
	    $this->status = FALSE; 
	    return; 
        } 

	/* 
	 * get the ?status information (cached or not) and parse it 
         * to populate the node information and modules' array. 
         */ 
	$info = $this->getStatus($comonode, $G['RESULTS'], "status");
	if ($info == FALSE) {
	    $this->status = FALSE; 
	    return; 
        } 

	for ($i = 0; $i < count($info); $i++) {
	    if ($info[$i] == "\n") 
		continue; 

	    /* get the first word of the line */ 
	    $lines = explode(" ", $info[$i], 2);

	    /* fields are separated by | */ 
	    $args = explode("|", $lines[1]);

	    $val = trim($lines[0]); 
	    switch ($val) {
	    case "Node:":
		list($this->nodename,$this->nodeplace,$this->linkspeed) = $args;
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
		$module = trim($args[0]);
		$this->modinfo[$module]['filter'] = urlencode(trim($args[1]));
		$this->modinfo[$module]['stime'] = trim($args[2]);
		$this->modinfo[$module]['formats'] = trim($args[3]);
		if (count($args) > 4)
		    $this->modinfo[$module]['name'] = trim($args[4]);
		else 
		    $this->modinfo[$module]['name'] = $module; 
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

	/*
	 * set current time interval 
	 */ 
	$this->etime = $this->curtime;
	$this->stime = $this->etime - $G['TIMEPERIOD'];

	/*  Make sure start time is not before the module start time  */
	if ($this->stime < $this->modinfo[$module]['stime'])
	    $this->stime = $this->modinfo[$module]['stime'];

	/*
	 *  all timestamps are always aligned to the timebound
	 *  defined in the comolive.conf file.
	 */
	$this->stime -= $this->stime % $G['TIMEBOUND'];
	$this->etime -= $this->etime % $G['TIMEBOUND'];
    }


    /* 
     * -- queryDir
     * 
     * browse a directory ($dadirname) to find a file with a 
     * name that contains the $needle. if no file is found 
     * return FALSE. 
     */ 
    function queryDir($dadirname, $needle) {
        $dh = opendir("$dadirname");

	while (FALSE !== ($file = readdir($dh))) 
	    if (strstr($file, $needle)) 
		return $file; 
		
	return FALSE; 
    }

    /* 
     * -- getStatus 
     * 
     * look if we have a recent copy of the status query. if
     * not, send a query to the node and store the results for 
     * future reference. return the contents of the file. 
     *
     */
    private function getStatus() {
        $statuslife = "600";
        $timenow = time();

        /*  Get the current status file  */
	$needlefile = $this->hostaddr . ":" . $this->hostport . "_status_"; 
        $statusfile = $this->queryDir($this->results, $needlefile);

        if ($statusfile != FALSE) {
	    /* 
	     * make sure the file is up-to-date. the name contains
             * the timestamp and it needs to be less than $statuslife 
             * seconds old. 
             */
	    $tmpvar = split("_", $statusfile);
	    $statusfilename = "$this->results/$statusfile";
	    if (($timenow - $tmpvar[2]) > $statuslife)
                system ("rm -f $statusfilename");
	    else 
		return file($statusfilename); 
        } 

	/* run the ?status query */
	$info = file("http://$this->hostaddr:$this->hostport/?status");
	if ($info == FALSE) 
	    return FALSE; 

	/* store the new ?status query results */
	$statusfilename = "$this->results/$needlefile$timenow";
        file_put_contents($statusfilename, $info); 

        return $info; 
    }
    
    function removeFile($filename) {
	system ("rm -f $this->results/$filename");
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

    function CheckFirstPacket($stime, $mod) {
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
    function GetModules($needle) {
        $keys = array_keys($this->modinfo);
        $modules = array();
        for ($i = 0; $i < count($keys); $i++) {
            $haystack = $this->modinfo[$keys[$i]]['formats'];
            if (strstr($haystack, $needle)) {
                array_push ($modules, $keys[$i]);
            }
        }
        return ($modules);
    }


    /* 
     * -- parseConfig
     * 
     * parses a module config file to find all modules listed 
     * as "main" or "secondary". It returns an array with the module 
     * names. 
     *
     */
    private function parseConfig($config, $value) {

	/* search the line with the $value modules */
	for ($i = 0; $i < count($config); $i++) {
	    if (strstr($config[$i], $value)) { 
		$tmp = $config[$i];
		break;
	    }
	}

	$res = explode (";;", $tmp);
       
	/* trim out the new line  */   
	for ($i = 0; $i < count($res); $i++)
	    $res[$i] = trim($res[$i]);

	return ($res);
    } 

    /*  
     * -- getConfig
     * 
     * Return an array with the modules that a user has chosen that 
     * are saved in a config file. Appropriate values for value are 
     * "main" for the main window and "secondary" for the right hand queries
     * 
     */
    function getConfig($comonode, $value) {
	$filename = "$this->db_path/$this->hostaddr:$this->hostport"."_modules";
	$config = file($filename); 
	if ($config == FALSE) {  
	    /* create a default config file */ 
	    $usable_mods = $this->getModules("gnuplot");
	    $config = "main";
	    for ($i = 0; $i < count($usable_mods); $i++) {
		$config = $config . ";;"; 
		$config = $config . $usable_mods[$i];
	    }
	    $config = $config . "\n"; 
	    $config = $config . "secondary;;alert;;topdest;;topports\n";
	    file_put_contents($filename, $config); 
	} 

	/* parse the config information */
	return $this->parseConfig($config, $value); 
    }
}
?>
