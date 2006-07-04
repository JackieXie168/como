<!--  $Id$  -->

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
    var $load;
    var $linkspeed;
    var $version;
    var $builddate;
    var $comostime;             /* Time como was started */
    var $curtime;
    var $modinfo;
    var $module;
    var $filter;
 
    var $start; 		/* query start and end time */ 
    var $end; 		/* XXX unclear why we need to keep it here */

    /* 
     * constructor for the class. 
     * this will run a ?status query (unless it is already cached) 
     * and store all information about the node and the modules
     * that are currently running. 
     */
    function Node($comonode, $G) 
    {
	$this->status = 1; 
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
	    $this->status = 0; 
	    return; 
        } 

	/* 
	 * get the ?status information (cached or not) and parse it 
         * to populate the node information and modules' array. 
         */ 
	$info = $this->getStatus();
	if ($info == FALSE) {
	    $this->status = 0; 
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
		$this->comostime = $args[0];
		break;

	    case "Current:":
		$this->curtime = $args[0];
		break;

	    case "Comment:":
		$this->comment = $args[0];
		break;

	    case "Load:":
		$this->load[0] = $args[0];
		$this->load[1] = $args[1];
		$this->load[2] = $args[2];
		$this->load[3] = $args[3];
		break;

	    case "Module:":
		$module = trim($args[0]);
		$this->modinfo[$module]['filter'] = urlencode(trim($args[1]));
		$this->modinfo[$module]['start'] = trim($args[2]);
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
	$this->end = $this->curtime;
	$this->start = $this->end - $G['TIMEPERIOD'];

	/*  Make sure start time is not before the module start time  */
	if ($this->start < $this->modinfo[$module]['start'])
	    $this->start = $this->modinfo[$module]['start'];

	/*
	 *  all timestamps are always aligned to the timebound
	 *  defined in the comolive.conf file.
	 */
	$this->start -= $this->start % $G['TIMEBOUND'];
	$this->end -= $this->end % $G['TIMEBOUND'];

    }

    /* 
     * -- queryDir
     * 
     * browse a directory ($dadirname) to find a file with a 
     * name that contains the $needle. if no file is found 
     * return FALSE. 
     */ 
    function queryDir($dadirname, $needle) 
    {
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
    private function getStatus() 
    {
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
    
    function removeFile($filename)
    {
	system ("rm -f $this->results/$filename");
    }


    function SetStarttime ($start) 
    {
        $this->start = $start;
    }

    function SetEndtime ($end) 
    {
        $this->end = $end;
    }

    function CheckFirstPacket($start, $mod) 
    {
        if ($start < $this->modinfo[$mod]['start']){
            $this->start = $this->modinfo[$mod]['start'];
        } else {
            $this->start = $start;
        }
        return $this->start;
    }

    /*  Return a list of modules that support different features  
     *  needle may be gnuplot, html, etc.  This info is captured
     *  on a per module basis.  
     */
    function getModules($needle) 
    {
        $keys = array_keys($this->modinfo);
        $modules = array();
        for ($i = 0; $i < count($keys); $i++) {
            $haystack = $this->modinfo[$keys[$i]]['formats'];
            if (strstr($haystack, $needle)) {
                array_push($modules, $keys[$i]);
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
    private function parseConfig($config, $which) 
    {
	/* 
	 * search the config array for $which 
   	 */ 
	for ($i = 0; $i < count($config); $i++) {
	    $res = explode(";;", $config[$i]); 
	    if ($res[0] == $which) 
		break;
	}

	/* 
	 * get rid of the first element and
         * trim whitespaces and carriage return 
         */ 
	array_shift($res); 
	for ($i = 0; $i < count($res); $i++) 
	    $res[$i] = trim($res[$i]);
	return $res;
    } 

    /*  
     * -- getConfig
     * 
     * Return an array with the modules that a user has chosen that 
     * are saved in a config file. Appropriate values for 'which' are 
     * "main" for the main window and "secondary" for the right hand queries
     * 
     */
    function getConfig($which) 
    {
	$filename = "$this->db_path/$this->hostaddr:$this->hostport"."_modules";
	if (file_exists($filename) == false) { 
	    /* create a default config file */ 
	    $usable_mods = $this->getModules("gnuplot");
	    $config[0] = "main";
	    for ($i = 0; $i < count($usable_mods); $i++) {
		$config[0] = $config[0] . ";;"; 
		$config[0] = $config[0] . $usable_mods[$i];
	    }
	    $config[0] = $config[0] . "\n"; 
	    $config[1] = "secondary;;alert;;topdest;;topports\n";
	    file_put_contents($filename, $config); 
	} else {
	    $config = file($filename); 
	}

	/* parse the config information */
	return $this->parseConfig($config, $which); 
    }

    /* 
     * -- saveConfig
     * 
     * Saves to file a list of modules splitting them in 
     * two categories: 'main', if they support gnuplot, 'secondary' 
     * if they support only html. 
     * 
     */ 
    function saveConfig($mods) 
    { 
	$filename = "$this->db_path/$this->hostaddr:$this->hostport"."_modules";
	$mainline = "main"; 
	$secline = "secondary"; 

	for ($i = 0; $i < count($mods); $i++) {
	    $formats = $this->modinfo[$mods[$i]]['formats'];
	    if (strstr($formats, "gnuplot"))
		$mainline = $mainline . ";;" . $mods[$i]; 
	    else if (strstr($formats, "html"))
		$secline = $secline . ";;" . $mods[$i]; 
	} 

	file_put_contents($filename, "$mainline\n$secline"); 
    } 

    /* 
     * -- module_args 
     * 
     * this method returns a list of arguments that are 
     * specific to this node and the module '$name'. it 
     * receives as input the time window and a list of additional 
     * arguments from the caller. 
     * 
     * XXX in the future most of these arguments should come 
     *     directly from the ?status query. 
     * 
     * XXX this function contains a significant amount of hard-wired
     *     information about modules. it should disappear in the 
     *     long term. 
     */  
    function module_args($name, $start, $end, $args)
    {
	// $modargs = "filter={$this->modinfo[$name]['filter']}&";
	$modargs = "";
	$interval = $end - $start;
	switch ($name) {
	case "alert":
	    $modargs = $modargs . "url=dashboard.php&";
	    $modargs = $modargs . "urlargs=comonode=";
            $modargs = $modargs . "{$this->hostaddr}:{$this->hostport}&";
	    break;

	case "topdest":
        case "topdst": 
        case "topsrc": 
	    $cookiename = "topn" . $name; 
	    if (!(isset($_COOKIE[$cookiename]))) {
		setcookie($cookiename, "5");
		$items = 5;
	    } else
		$items = $_COOKIE[$cookiename];

	    $modargs = $modargs . "source=tuple&";
	    $modargs = $modargs . "interval=$interval&";
	    $modargs = $modargs . "align-to=$start&";
	    $modargs = $modargs . "topn=$items&";
	    $modargs = $modargs . "url=generic_query.php&";
	    $modargs = $modargs . "urlargs=start=$start&";
	    $modargs = $modargs . "urlargs=end=$end&";
	    $modargs = $modargs . "urlargs=interval=$interval&";
	    $modargs = $modargs . "urlargs=module=tuple&";
	    $modargs = $modargs . "urlargs=source=tuple&";
	    if ($args['useblincview']) {
		$modargs = $modargs . "urlargs=format=plain&";
		$modargs = $modargs . "urlargs=extra=blincview&";
	    } else {
		$modargs = $modargs . "urlargs=format=html&";
	    }
	    break;

	case "topports":
	    $cookiename = "topn" . $name; 
	    if (!(isset($_COOKIE[$cookiename]))) {
		setcookie($cookiename, "5");
		$items = 5;
	    } else
		$items = $_COOKIE[$cookiename];

	    $modargs = $modargs . "topn=$items&";
	    $modargs = $modargs . "align-to=$start&";
	    $modargs = $modargs . "source=tuple&";
	    $modargs = $modargs . "interval=$interval&";
	    break;

        case "unknowns": 
	    $modargs = $modargs . "source=tuple&";
	    $modargs = $modargs . "interval=$interval&";
	    $modargs = $modargs . "align-to=$start&";
	    $modargs = $modargs . "url=generic_query.php&";
	    $modargs = $modargs . "urlargs=start=$start&";
	    $modargs = $modargs . "urlargs=end=$end&";
	    $modargs = $modargs . "urlargs=interval=$interval&";
	    $modargs = $modargs . "urlargs=module=tuple&";
	    $modargs = $modargs . "urlargs=source=tuple&";
	    $modargs = $modargs . "urlargs=format=html&";
	    $modargs = $modargs .
		       "urlargs=comonode={$this->hostaddr}:{$this->hostport}&";
	    break; 
	}

	return $modargs;
    }
}
?>
