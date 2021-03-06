<!-- $Id: customize.php 897 2006-10-19 15:00:30Z rgass $ --> 
<?php
    $ABSROOT = preg_replace('/\/groups.*/', '', $_SERVER['SCRIPT_FILENAME']);

    require_once ("$ABSROOT/comolive.conf");
    $G = init_global();
    require_once ("class/node.class.php");
    include_once ("include/framing.php");
    function failure_message() 
    { 
	print_header(0, null);
	
        print "<div id=content>"; 
        print "<div class=graph>";
        print "<br><br><center>";
        print "Sorry but the requested CoMo node is not <br>";
        print "available at the moment. Please try another time.<br><br>";
        print "</div></div>";

	print_footer();
    } 
    function print_modules($node, $which)
    { 
	/* 
	 * browse the list of modules and print the name, the first 
	 * available timestamp, the filter and the description. modules
	 * that are currently shown will have the box checked and a
	 * different color. 
	 * 
	 * $which indicates the set of modules we are interested in: 
	 *  . modules that support gnuplot (main modules); 
	 *  . modules that support html (secondary modules); 
	 * 
	 */
        $allmodules = $node->getAllModules();
        foreach ($allmodules as $m) {
            if ($which == 'main') {
                if ($node->isModuleMain($m)) {
                    $mods[] = $m;
                }
            }
            else if ($node->isModuleSecondary($m)) {
                $mods[] = $m;
            }
        }

        $selected = $node->getConfig($which); 

	for ($i = 0; $i < count($mods); $i++) {
	    $is_selected = in_array($mods[$i], $selected); 
	    $cl = $is_selected? "module_selected" : "module_normal"; 
	    $timestr = gmstrftime("%a %b %d %T %Y", 
				  $node->modinfo[$mods[$i]]['start']);
	    $fl = urldecode($node->modinfo[$mods[$i]]['filter']);
            $cust_info[$i]['class'] = $cl;
            $cust_info[$i]['mods'] = $mods[$i];
            
	    if ($is_selected) {
                $cust_info[$i]['isselected'] = "checked";
            } else {
                $cust_info[$i]['isselected'] = "";
            }
            $cust_info[$i]['modname'] = $node->modinfo[$mods[$i]]['name'];
            $cust_info[$i]['timestr'] = $timestr;
            $cust_info[$i]['fl'] = $fl;
	}
        return ($cust_info);
    } 

    $G = init_global();

    /*
     * if the configuration file prohibits customization, 
     * return an error message and exit. 
     */
    if (!$G['ALLOWCUSTOMIZE']) {
	print_header(0, null);
        print "Customization of CoMoLive is NOT allowed<br>";
        print "Please check your comolive.conf file<br>";
	print_footer(0);
        exit;
    }

    /* 
     * get the node hostname and port number from the HTTP 
     * query string and initialize the new node. 
     */
    if (!isset($_GET['comonode'])) {
	print "{$_SERVER['SCRIPT_FILENAME']}";
        print " requires the comonode=host:port arg passed to it";
	exit;
    }

    $comonode = $_GET['comonode'];

    /* 
     * initialize a new node by querying the node for the current 
     * status. If the query fails return an error message. 
     */
    $node = new Node($comonode, $G);
    if ($node->status == false) {
	failure_message(); 
	exit; 
    } 

    if (isset($_GET['action']))
	$action = $_GET['action'];
    else
	$action = "NORM";

    /* Write out new config file  */
    if ($action == "submit") {
	/* 
	 * extract the list of modules that have been selected and 
	 * save them in the config file 
	 */ 
	$val = explode ("&", $_SERVER['QUERY_STRING']);
	$allmods = array_merge($node->getModules('gnuplot'), 
		               $node->getModules('html')); 

	$selectmods = array(); 
	for ($i = 0; $i < count($val); $i++) { 
	    $k = explode("=", $val[$i]); 
	    if (in_array($k[1], $allmods)) 
		array_push($selectmods, $k[1]); 
	} 

	$node->saveConfig($selectmods); 
    }

    $header = simple_header("$G['WEBROOT']"); 

    $main_info = print_modules($node, 'main');
    $sec_info = print_modules($node, 'secondary');
    include ("html/customize.html");
?>

