<!--  $Id$  -->

<?php
    require_once("comolive.conf");		/* init_global */
    require_once("class/node.class.php");	/* Node class */
    require_once("include/framing.php"); 	/* header/footer functions */

    /*  Create a cookie and initialize to all fields visible  */
    if (!(isset($_COOKIE['alert'])))
	setcookie("alert", "block");
    if (!(isset($_COOKIE['topdest'])))
	setcookie("topdest", "block");
    if (!(isset($_COOKIE['topports'])))
	setcookie("topports", "block");
    if (!(isset($_COOKIE['topntopdest']))) {
	setcookie("topntopdest", "5");
        $topntopdest = 5;
    } else 
        $topntopdest = $_COOKIE['topntopdest'];
 
    if (!(isset($_COOKIE['topntopports']))) {
	setcookie("topntopports", "5");
        $topntopports = 5;
    } else 
        $topntopports = $_COOKIE['topntopports'];

    /*  get the node hostname and port number */
    if (!isset($_GET['comonode'])) {
	print "This file requires the comonode=host:port arg passed to it<br>";
	print "Thanks for playing!<br><br><br><br><br><br><br>";
	include("include/footer.php.inc");
	exit;
    }

    $comonode = $_GET['comonode'];
    print_header(1, $comonode); 

    $G = init_global(); 

    include("include/getinputvars.php.inc");

    $node = new Node($comonode, $G);
    if ($node->status == FALSE) { 
	/* cannot connect to node, fail with error */
        print "<center>An attempt to query $comonode has failed.<br>";
        print "Please ensure hostname and port are correct and try again.<br>";
	print "<br><br><br><br><br><br>";
	print_footer(); 
	exit;
    }

    /*
     * GET input variables
     */
    $input_vars = init_env($node);
    $module = $input_vars['module'];
    $filter = $input_vars['filter'];
    $etime = $input_vars['etime'];
    $stime = $input_vars['stime'];
    $format = $input_vars['format'];
    $http_query_string = $input_vars['http_query_string'];

    
    /*  Check if this is a distributed query  
     *  Eventually this will be a como module, however, we will hard 
     *  code it to get an idea of our future direction
     */
#    if ($module == "distquery") {
#print "module is $module and comonode is $comonode< br>";
#        print "this is a distributed query<br>";
#        print "currently not supported<br>";
#        exit;
#    }
?>

<body>
<script type="text/javascript">
    <!--
window.onload = function() {
    initializeMenu("alertMenu", "alertTrig", "alertImage", "alert");
    initializeConfigMenu("alertMenuedit", "alertTrigedit", "alertedit");
    initializeMenu("topdestMenu", "topdestTrig", "topdestImage", "topdest");
    initializeConfigMenu("topdestMenuedit", "topdestTrigedit", "topdestedit");
    initializeMenu("topportsMenu", "topportsTrig", "topportsImage", "topports");
    initializeConfigMenu("topportsMenuedit", "topportsTrigedit", "topportsedit");
}
    if (!document.getElementById)
	document.getElementById = function() { return null; }

function initializeConfigMenu(menuId, triggerId, module) {
    var menu = document.getElementById(menuId);
    var trigger = document.getElementById(triggerId);
    menu.style.display = "none"; 

    trigger.onclick = function() {
        var display = menu.style.display;
        if (display == "block")
	    menu.style.display = "none";
        else
	    menu.style.display = "block";
     
    }
}

function readCookie(name) {
    var nameEQ = name + "=";
    var ca = document.cookie.split(';');
    for(var i=0;i < ca.length;i++) {
	var c = ca[i];
	while (c.charAt(0)==' ') c = c.substring(1,c.length);
	    if (c.indexOf(nameEQ) == 0) 
		return c.substring(nameEQ.length,c.length);
    }
    return null;
}


function initializeMenu(menuId, triggerId, imageId, module) {
    var menu = document.getElementById(menuId);
    var trigger = document.getElementById(triggerId);
    var image = document.getElementById(imageId); 
    var state = readCookie(module);
    menu.style.display = state; 
    var display = menu.style.display;
    image.src = (display == "block")? "images/minus.gif" : "images/plus.gif";

    trigger.onclick = function() {
        var display = menu.style.display;
	if (display == "block") { 
	    image.src = "images/plus.gif"; 
	    menu.style.display = "none"; 
	    document.cookie = module + "=none"; 
        } else { 
	    image.src = "images/minus.gif"; 
	    menu.style.display = "block"; 
	    document.cookie = module + "=block"; 
        } 
        return false;
    }

    function readCookie(name) {
	var nameEQ = name + "=";
	var ca = document.cookie.split(';');
	for(var i=0;i < ca.length;i++) {
	    var c = ca[i];
	    while (c.charAt(0)==' ') c = c.substring(1,c.length);
		if (c.indexOf(nameEQ) == 0) 
                    return c.substring(nameEQ.length,c.length);
	}
	return null;
    }
}
    //-->
</script>

<style>
    #sidebox_bar {
        background-color: #475677;
        text-align: left;
	padding: 2px;
	margin: 0px;
    }
    #sidebox_bar a,a:visited {
	color: #FFF; 
    } 
    .sidebox_name {
	font-family: "lucida sans unicode", verdana, arial;
	font-size: 9pt; 
	font-weight: bold;
	color: #FFF; 
    } 
    .sidebox_edit { 
	#position: absolute; 
	#right: 30px; 
	font-weight: normal;
	margin-left: 10px;
    } 
    .sidebox_image { 
	padding-left: 2px; 
	margin-right: 10px; 
    } 
    .sidebox_content {
	margin: 1px;
    } 
</style>

<table class=fence border=0 cellpadding=0 cellspacing=0>
  <tr>
    <td colspan=2>
    <table class=topcontent border=0 cellpadding=0 cellspacing=0>
      <tr>
	<td valign=top width=50%>
	  <?php include "sysinfo.php"; ?>
	</td>
	<td valign=top>
	  <?php include("netview.php"); ?>
	</td>
      </tr>
    </table>
  </td>
  <tr>
    <td class=leftcontent>
      <iframe width=620 height=520 frameborder=0
	      src=mainstage.php?<?=$http_query_string?>>
      </iframe>
    </td>
    <td class=rightcontent>
      <?php 
	  /* 
	   * this is the right side of the page. it will contain some
	   * iframes to include the time range the page refers to (netview)
	   * 
	   * XXX  This is a config option now
	   * 
	   */


          $sec_array = $node->getConfig("secondary");
          $interval=$etime-$stime;
          for ($i = 0; $i < count($sec_array); $i++) {
	      /*  Hard code module specific options here  */
	      $modargs = "";
	      if ($sec_array[$i] == "alert"){
		$modargs = "filter={$node->modinfo[$sec_array[$i]]['filter']}&";
		$modargs = $modargs . "url=dashboard.php&";
	      }
	      if ($sec_array[$i] == "topdest"){
		$modargs = "filter={$node->modinfo[$sec_array[$i]]['filter']}&";
		$modargs = $modargs . "source=tuple&";
		$modargs = $modargs . "interval=$interval&";
                $modargs = $modargs . "align-to=$stime&";
		$modargs = $modargs . "topn=$topntopdest&";
		$modargs = $modargs . "url=generic_query.php&";
		$modargs = $modargs . "urlargs=stime=$stime&";
		$modargs = $modargs . "urlargs=etime=$etime&";
		$modargs = $modargs . "urlargs=interval=$interval&";
		$modargs = $modargs . "urlargs=module=tuple&";
		$modargs = $modargs . "urlargs=source=tuple&";
                if ($G['USEBLINCVIEW']) {
		    $modargs = $modargs . "urlargs=format=plain&";
		    $modargs = $modargs . "urlargs=extra=blincview&";
                } else
		    $modargs = $modargs . "urlargs=format=html&";
	      }
	      if ($sec_array[$i] == "topports"){
		$modargs = "filter={$node->modinfo[$sec_array[$i]]['filter']}&";
		$modargs = $modargs . "topn=$topntopports&";
                $modargs = $modargs . "align-to=$stime&";
		$modargs = $modargs . "source=tuple&";
		$modargs = $modargs . "interval=$interval&";
	      }

              /*  This is where the iframes is printed out  */
              #print "<form target=frame$i ";
              print "<form target=frame$i ";
              print "name=topn$sec_array[$i] ";
	      print "action=generic_query.php?comonode=$comonode&";
	      print "module={$sec_array[$i]}&format=html&";
	      print "stime=$stime&etime=$etime&";
	      print "$modargs";
	      print "urlargs=comonode=$comonode& ";
              print "method=POST>";

              /* sidebox label */
              print "<div id=sidebox_bar>";
	      print "<a href=# id=$sec_array[$i]Trig class=sidebox_name>";
              print "<img src=images/plus.gif id=$sec_array[$i]Image 
                          class=sidebox_image>"; 
              print "{$node->modinfo[$sec_array[$i]]['name']}</a>";
	      print "<a href=# id=$sec_array[$i]Trigedit class=sidebox_edit>";
              print "[edit]</a>";
              print "</div>";

	      /* edit dropdown */
              print "<div id=$sec_array[$i]Menuedit>";
              print "Show ";
              print "<input type=textbox size=1 name=topn$sec_array[$i]>";
              print " items ";
              print "<input type=submit value=Save>";
              print "</div>";

              /* sidebox content */ 
              print "<div id=$sec_array[$i]Menu class=sidebox_content>";
	      print "\n\n<iframe width=100% frameborder=0 ";
	      print "name=frame$i ";
	      print "src=generic_query.php?comonode=$comonode&";
	      print "module={$sec_array[$i]}&format=html&";
	      print "stime=$stime&etime=$etime&";
	      print "$modargs";
	      print "urlargs=comonode=$comonode&";
#	      print "urlargs=module=$module&";
	      print "urlargs=filter={$node->modinfo[$sec_array[$i]]['filter']}>";
	      print "</iframe>\n\n";
              print "</div>\n";
              print "</form>";
	  }
      ?>
    </td>
  </tr>
</table>

<?php 
    print_footer(); 
?>
