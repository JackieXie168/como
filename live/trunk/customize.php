<!-- $Id$ --> 

<?php
    $pagetitle="Customize CoMo";
    $includebanner=0;
    include ("include/header.php.inc");
    require_once("comolive.conf");
    $G = init_global();
    $ALLOWCUSTOMIZE = $G['ALLOWCUSTOMIZE'];
    $NODEDB = $G['NODEDB'];
    require_once("class/node.class.php");
  
    /*
     * if the configuration file prohibits customization, 
     * return an error message and exit. 
     */
    if (!($ALLOWCUSTOMIZE)){
        print "Customization of CoMoLive is NOT allowed<br>";
        print "Please check your comolive.conf file<br>";
        exit;

    }

    /* 
     * get the node hostname and port number from the HTTP 
     * query string and initialize the new node. 
     */
    if (isset($_GET['comonode'])) {
	$comonode = $_GET['comonode'];
    } else {
	print "{$_SERVER['SCRIPT_FILENAME']}";
        print " requires the comonode=host:port arg passed to it";
	exit;
    }

    /* 
     * initialize a new node by querying the node for the current 
     * status. If the query fails return an error message. 
     */
    $node = new Node($comonode,$G);
    if ($node->status == "FAIL") {
        /*
         * query failed. write error message and exit
         */
        include("include/header.php.inc");
    ?>
        <div id=content>
          <div class=graph">
          <br><br><center>
            Sorry but the requested CoMo node is not <br>
            available at the moment. Please try another time.<br><br>
          </div>
        </div>
    <?php
        include("include/footer.php.inc");
        exit;
    }

    /* 
     * build two arrays with nodes that support images (and can be 
     * on the main stage) and nodes that can return html files (and can 
     * go in the side boxes). 
     */
    $mainmods = $node -> GetModules("gnuplot");
    $secmods = $node -> GetModules("html");

    if (isset($_GET['action']))
	$action = $_GET['action'];
    else
	$action = "NORM";

/*  Write out new config file  */
    if ($action == "submit") {
	$val = explode ("&", $_SERVER['QUERY_STRING']);
print "val is $val";
	$secfile = "sec_mods";
	$mainfile = "main_mods";
	for ($i = 0; $i < count($val); $i++) {
	    if (strstr($val[$i], "mainmods")){
		$mainfile = $mainfile . ";;";
		$mod = explode ("=", $val[$i]);
		$mainfile = $mainfile . $mod[1];
	    }
	}
	$mainfile = $mainfile . "\n";
	for ($i = 0; $i < count($val); $i++) {
	    if (strstr($val[$i], "secmods")){
		$secfile = $secfile . ";;";
		$mod = explode ("=", $val[$i]);
		$secfile = $secfile . $mod[1];
	    }
	}
	$secfile = $secfile . "\n";
	$dadirname = $G['ABSROOT'] . "/" . $G['NODEDB'];
	$needlefile = $comonode . "_config_";
	$configfilename = $node -> queryDir ($dadirname, $needlefile);
	if ($fh = fopen ("$NODEDB/$configfilename", "w")) {
	    fwrite ($fh, $mainfile);
	    fwrite ($fh, $secfile);
	    fclose ($fh);
	}
    }
    /*  Read config file  */
    $dadirname = $G['ABSROOT'] . "/" . $G['NODEDB'];
    $needlefile = $comonode . "_config_";
    $configfilename = $node -> queryDir ($dadirname, $needlefile);
    $configfilename = $dadirname . "/" . $configfilename;
    if (file_exists($configfilename)) {
        $dafile = file ($configfilename);
	for ($i=0;$i<count($dafile);$i++){
	    if (strstr($dafile[$i], "sec_mods")) {
                $secfile = $dafile[$i];
	    }
	    if (strstr($dafile[$i], "main_mods")) {
                $mainfile = $dafile[$i];
	    }
        }
    }
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
      <?php
	  /* 
	   * browse the list of modules and print the name, the first 
	   * available timestamp, the filter and the description. modules
	   * that are currently shown will have the box checked and a
	   * different color. 
	   */
	  for ($i = 0; $i < count($mainmods); $i++) {
	      $cl = "module_normal"; 
              if (strstr($mainfile, $mainmods[$i]))
		  $cl = "module_selected"; 
              print "<table class=$cl style=\"border:1px dashed; width:100%\">\n";
	      print "<tr><td colspan=2 class=$cl>\n";
	      print "<input name=mainmods ";
	      if (strstr($mainfile, $mainmods[$i]))
		  print " checked ";
	      print "type=checkbox value=$mainmods[$i]>";
	      print "$mainmods[$i]"; 
	      print "</td></tr>\n";
              print "<tr><td class=$cl>\n";
	      print "Description goes here</td>\n"; 
              print "<td class=$cl>\n";
	      print "Online since: <br>\n"; 
	      $st = $node->modinfo[$mainmods[$i]]['stime'];
	      $timestr = gmstrftime("%a %b %d %T %Y", $st);
	      print "<i>$timestr</i><br>\n"; 
	      print "Running filter: <br>\n"; 
	      $fl = $node->modinfo[$mainmods[$i]]['filter'];
              $fl = urldecode($fl);
	      print "<i>'$fl'</i>";
	      print "</td></tr>\n";
	      print "</table>\n";
	  }
      ?>
    </td>
    <td class=box>
      <?php
          /*
           * browse the list of modules and print the name, the first
           * available timestamp, the filter and the description. modules
           * that are currently shown will have the box checked and a
           * different color.
           */
          for ($i = 0; $i < count($secmods); $i++) {
	      $cl = "module_normal"; 
              if (strstr($secfile, $secmods[$i]))
		  $cl = "module_selected"; 
              print "<table class=$cl style=\"border:1px dashed; width:100%;\">\n";
	      print "<tr><td colspan=2 class=$cl>\n";
              print "<input name=secmods ";
              if (strstr($secfile, $secmods[$i]))
                  print " checked ";
              print "type=checkbox value=$secmods[$i]>";
              print "$secmods[$i]";
              print "</td></tr>\n";
              print "<tr><td class=$cl>\n";
              print "Description goes here</td>\n";
              print "<td class=$cl>\n";
              print "Online since: <br>\n";
              $st = $node->modinfo[$secmods[$i]]['stime'];
              $timestr = gmstrftime("%a %b %d %T %Y", $st);
              print "<i>$timestr</i><br>\n";
              print "Running filter: <br>\n";
              $fl = $node->modinfo[$secmods[$i]]['filter'];
              $fl = urldecode($fl);
              print "<i>'$fl'</i>";
              print "</td></tr>\n";
              print "</table>\n";
          }
      ?>

    </td>
  </tr>
</table>
</form>
</body>
</html>
