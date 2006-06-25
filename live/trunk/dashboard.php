<!--  $Id$  -->

<?php
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

    /* parse input variables */ 
    $iv = init_env($node);

    /* prepare variables for time interval */ 
    $startstr = gmstrftime("%a %b %d %T %Y", $iv['stime']);
    $endstr = gmstrftime("%a %b %d %T %Y", $iv['etime']);
    $firstpacket = gmstrftime("%a %b %d %T %Y", 
		              $node->modinfo[$iv['module']]['stime']);
    $duration = $iv['etime'] - $iv['stime'];
    $days = floor($duration / 86400);
    $hours = floor(($duration % 86400) / 3600);
    $mins = floor(($duration % 3600) / 60);
    $secs = $duration % 60;

    /* 
     * prepare text for vcr-style buttons 
     */ 
    $base = "dashboard.php?comonode=$comonode&module={$iv['module']}";

    $st = $iv['etime'] - 900;
    $query_15m = "$base&stime=$st&etime={$iv['etime']}";
    $st = $iv['etime'] - 3600;
    $query_1h = "$base&stime=$st&etime={$iv['etime']}";
    $st = $iv['etime'] - 3600*6;
    $query_6h = "$base&stime=$st&etime={$iv['etime']}";
    $st = $iv['etime'] - 86400;
    $query_1d = "$base&stime=$st&etime={$iv['etime']}";

    $zoomin = zoom_in($iv['stime'],$iv['etime'],$node,$base,$G['TIMEBOUND']); 
    $zoomout = zoom_out($iv['stime'],$iv['etime'],$node,$base,$G['TIMEBOUND']); 
    $fwd = forward($iv['stime'],$iv['etime'],$node,$base,$G['TIMEBOUND']); 
    $bwd = backward($iv['stime'],$iv['etime'],$node,$base,$G['TIMEBOUND']); 

    $now = $node->curtime - ($node->curtime % $G['TIMEBOUND']);
    $fwd_now = until_now($iv['stime'], $now, $base); 

    $tmp = "generic_query.php?comonode=$comonode&module=tuple&source=tuple&";
    $tmp = $tmp . "interval=$duration&stime={$iv['stime']}&"; 
    $tmp = $tmp . "etime={$iv['etime']}&format=html";
    $details = detail_button($tmp);

    /* 
     * prepare search bar 
     */ 
    $searchquery = "search.php?comonode=$comonode&module=tuple&source=tuple&" .
		   "interval=$duration&stime={$iv['stime']}&" .
		   "etime={$iv['etime']}&format=html";

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
				    $iv['stime'], 
				    $iv['etime'],
				    $args);
	 
	$query[$i] = "generic_query.php?$margs&module={$module[$i]}&" . 
	             "format=html&stime={$iv['stime']}&" . 
		     "etime={$iv['etime']}&comonode=$comonode";

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
