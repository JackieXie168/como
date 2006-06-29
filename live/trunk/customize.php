<!-- $Id$ --> 

<?php
    require_once "comolive.conf";
    require_once "class/node.class.php";
    include_once "include/framing.php"; 

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

    function print_modules($which, $node)
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
	$mods = $node->getModules($which);
	if ($which == "gnuplot") 
	    $selected = $node->getConfig("main"); 
	else 
	    $selected = $node->getConfig("secondary"); 

	for ($i = 0; $i < count($mods); $i++) {
	    $is_selected = in_array($mods[$i], $selected); 
	    $cl = $is_selected? "module_selected" : "module_normal"; 
	    $timestr = gmstrftime("%a %b %d %T %Y", 
				  $node->modinfo[$mods[$i]]['start']);
	    $fl = urldecode($node->modinfo[$mods[$i]]['filter']);

	    print "<table class=$cl style=\"border:1px dashed; width:100%\">\n";
	    print "<tr><td colspan=2 class=$cl>\n";
	    print "<input name=$mods[$i] ";
	    if ($is_selected) 
		print " checked ";
	    print "type=checkbox value=$mods[$i]>";
	    print "{$node->modinfo[$mods[$i]]['name']}"; 
	    print "</td></tr>\n";
	    print "<tr><td class=$cl>\n";
	    print "Description goes here</td>\n"; 
	    print "<td class=$cl>\n";
	    print "Online since: <br>\n"; 
	    print "<i>$timestr</i><br>\n"; 
	    print "Running filter: <br>\n"; 
	    print "<i>'$fl'</i>";
	    print "</td></tr>\n";
	    print "</table>\n";
	}
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

    print_header(0, null); 
?>

<style>
    body { 
	font-family : "lucida sans unicode", verdana, arial;
        font-size : 9pt; 
        margin : 0; 
        padding : 0;
    }
    table {
	font-family : "lucida sans unicode", verdana, arial;
        font-size : 9pt;
        width : 95%;
    }
    tr, td {
	background-color : #DDD;
	font-family : "lucida sans unicode", verdana, arial;
        font-size : 9pt;
    } 
    a, a:visited { 
	color : #475677; 
        text-decoration: none;
    }
    .box { 
	background-color : #FFF;
        padding : 0; 
	margin: 0; 
	border: 0; 
    } 
    .module_normal {
	background-color : #FFF;
        padding : 0; 
	border: 0;
	margin: 1;
    }
    .module_selected {
	background-color : #DDD;
        padding : 0; 
	border: 0;
	margin: 1;
    } 
    .region { 
	background-color : #FFF;
        border-top: 1px dashed #AAA;
        padding: 0;
        font-size : 12px;
        font-weight : bold;  
	color : #475677;
    } 
    .nodename {
	background-color : #475677;
        padding : 0px 10px 10px 10px ;
        font-size : 20px;
        color: #FFF; 
        font-weight : bold;  
        text-align : left;
        width: 50%;
    }
    .buttons {
	background-color : #DDD;
        padding : 0px 10px 10px 10px ;
        font-size : 10px;
        text-align : left;
    }

</style>

<body>
<form action="customize.php" method="GET">
<table>
  <tr>
    <td class=nodename>
      <?=$node->nodename?> 
    </td>
    <td class=buttons>
      Tick on the boxes below to customize the view of the main CoMo page. <br>
      <p align=right>
      <input type=submit value="Save"> 
      <input type=submit value="Done" OnClick=window.close(this);>
      <input type=hidden name=comonode value=<?=$comonode?>>
      <input type=hidden name=action value=submit>
    </td>
  </tr>
  <tr>
    <td class=region>
      Main Window 
    </td>
    <td class=region>
      Side Boxes
    </td>
  </tr>
  <tr valign=top>
    <td class=box>
      <?= print_modules('gnuplot', $node); ?>
    </td>
    <td class=box>
      <?= print_modules('html', $node); ?>
    </td>
  </tr>
</table>
</form>
</body>
</html>
