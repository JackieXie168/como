<?php
    /*  $Id$  */
    require_once "class/node.class.php";	/* Node class */
    require_once "include/framing.php"; 	/* header/footer functions */
    require_once "include/vcrbuttons.php";      /* zoom_in, zoom_out, etc. */
    require_once "include/getinputvars.php.inc";/* init_env */ 
    include_once "comolive.conf";		/* init_global */

    if (!file_exists("comolive.conf")) {
        print "Please create a comolive.conf file";
	exit; 
    }

    /*  get the node hostname and port number */
    if (!isset($_GET['comonode'])) {
	print "This file requires the comonode=host:port arg passed to it<br>";
	print "Thanks for playing!<br><br><br><br><br><br><br>";
	print do_footer(); 
	exit;
    }

    $comonode = $_GET['comonode'];

    $G = init_global(); 

    $node = new Node($comonode, $G);
    if ($node->status == false) { 
	/* cannot connect to node, fail with error */
	$header = do_header(NULL, 0); 
	$footer = do_footer(); 
	include "html/node_failure.html"; 
	exit;
    }
    /*  Check if there are running modules that support CoMoLive  */
    $nummods = count($node->getModules("gnuplot"));
    if ($nummods == 0) {
	$header = do_header(NULL, 0); 
	$footer = do_footer(); 
        $mes = "NOTICE<br>There are no running modules<br>";
        $mes = $mes . "that support the CoMoLive interface<br>";
        $mes = $mes . "Please check your modules.<br><br>";
        $mes = $mes . "Host = $comonode.<br>";
        $generic_message = $mes;
        include ("html/generic_message.html");
        exit;
    }

    /* parse input variables */ 
    $iv = init_env($node);

    /* prepare variables for time interval */ 
    $startstr = gmstrftime("%a %b %d %T %Y", $iv['start']);
    $endstr = gmstrftime("%a %b %d %T %Y", $iv['end']);
    $firstpacket = gmstrftime("%a %b %d %T %Y", 
		              $node->modinfo[$iv['module']]['start']);
    $duration = $iv['end'] - $iv['start'];
    $days = floor($duration / 86400);
    $hours = floor(($duration % 86400) / 3600);
    $mins = floor(($duration % 3600) / 60);
    $secs = $duration % 60;

    /* 
     * prepare text for vcr-style buttons 
     */ 
    $base = "dashboard.php?comonode=$comonode&module={$iv['module']}";

    $st = $iv['end'] - 900;
    $query_15m = "$base&start=$st&end={$iv['end']}";
    $st = $iv['end'] - 3600;
    $query_1h = "$base&start=$st&end={$iv['end']}";
    $st = $iv['end'] - 3600*6;
    $query_6h = "$base&start=$st&end={$iv['end']}";
    $st = $iv['end'] - 86400;
    $query_1d = "$base&start=$st&end={$iv['end']}";

    $zoomin = zoom_in($iv['start'],$iv['end'],$node,$base,$G['TIMEBOUND']); 
    $zoomout = zoom_out($iv['start'],$iv['end'],$node,$base,$G['TIMEBOUND']); 
    $fwd = forward($iv['start'],$iv['end'],$node,$base,$G['TIMEBOUND']); 
    $bwd = backward($iv['start'],$iv['end'],$node,$base,$G['TIMEBOUND']); 

    $now = $node->curtime - ($node->curtime % $G['TIMEBOUND']);
    $fwd_now = until_now($iv['start'], $now, $base); 

    $tmp = "generic_query.php?comonode=$comonode&module=tuple&source=tuple&";
    $tmp = $tmp . "interval=$duration&start={$iv['start']}&"; 
    $tmp = $tmp . "end={$iv['end']}&format=html";
    $details = detail_button($tmp);

    /* 
     * prepare search bar 
     */ 
    $searchquery = "search.php?comonode=$comonode&module=tuple&source=tuple&" .
		   "interval=$duration&start={$iv['start']}&" .
		   "end={$iv['end']}&format=html";

    /* 
     * prepare queries for sideboxes 
     */ 
    $module = $node->getConfig("secondary");
    $sideboxes = count($module); 
    $window_onload = "";

    $args['useblincview'] = $G['USEBLINCVIEW'];

    for ($i = 0; $i < count($module); $i++) {
	// add module-specific options
	$margs = $node->module_args($module[$i],
				    $iv['start'], 
				    $iv['end'],
				    $args);
	 
	$query[$i] = "generic_query.php?$margs&module={$module[$i]}&" . 
	             "format=html&start={$iv['start']}&" . 
		     "end={$iv['end']}&comonode=$comonode";

	$name[$i] = $node->modinfo[$module[$i]]['name'];

	/* create a cookie and initialize to be hidden */ 
	if (!(isset($_COOKIE[$module[$i]])))
	    setcookie($module[$i], "none");

	// prepare the javascript onload function 
	$window_onload = $window_onload . 
		"initializeMenu('{$module[$i]}');\n" . 
                "initializeConfigMenu('$module[$i]');\n"; 
    } 

    // prepare header and footer 
    $header = do_header($comonode, $G['ALLOWCUSTOMIZE']); 
    $footer = do_footer(); 

    // include the HTML template 
    include "html/dashboard.html"; 
?>
