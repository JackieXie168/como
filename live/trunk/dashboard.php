<?php
    /*  Create a cookie and initialize to all fields visible  */
    if (!(isset($_COOKIE['alert'])))
	setcookie("alert", "block");
    if (!(isset($_COOKIE['topdest'])))
	setcookie("topdest", "block");
    if (!(isset($_COOKIE['topports'])))
	setcookie("topports", "block");

?>
<!--  $Id$  -->

<?php
    $includebanner=1;
    include("include/header.php.inc");
    $includebanner=0;	/* we have one banner, avoid that others include it */
    /*  get the node hostname and port number */
    if (isset($_GET['comonode'])) {
	$comonode = $_GET['comonode'];
    } else {
	print "This file requires the comonode=host:port arg passed to it<br>";
	print "Thanks for playing!<br><br><br><br><br><br><br>";
	include("include/footer.php.inc");
	exit;
    }
    

    require_once ("comolive.conf");

    require_once ("class/node.class.php");
    include("include/getinputvars.php.inc");
    $node = new Node($comonode, $G);
    /*  If cannot connect to node, fail with error  */
    if ($node -> status == "FAIL") {
        print "<center>An attempt to query $node->comonode has failed.<br>";
        print "Please ensure hostname and port are correct and try again.<br>";
	print "<br><br><br><br><br><br>";
	include("include/footer.php.inc");
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
    initializeMenu("alertMenu", "alertTrig", "alert");
    initializeMenu("topdestMenu", "topdestTrig", "topdest");
    initializeMenu("topportsMenu", "topportsTrig", "topports");
}
    if (!document.getElementById)
	document.getElementById = function() { return null; }

function initializeMenu(menuId, triggerId, module) {
    var menu = document.getElementById(menuId);
    var trigger = document.getElementById(triggerId);
    var state = readCookie(module);
    menu.style.display = state; 
    var display = menu.style.display;
    menu.parentNode.style.backgroundImage =
            (display == "block") ? "url(images/plus.gif)" : 
                                   "url(images/minus.gif)";

    trigger.onclick = function() {
        var display = menu.style.display;
        this.parentNode.style.backgroundImage = 
        (display == "block") ? "url(images/minus.gif)" : "url(images/plus.gif)";
        menu.style.display = (display == "block") ? "none" : "block";
	/*document.cookie = module + "=" + display; */
	var opposite = (display=="block") ? "none" : "block";
	document.cookie = module+"="+opposite;
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
    .menubar {
        background : url(images/plus.gif) no-repeat 0em 0.3em; 
        background-color : #EEE;
        text-align : left;
    }
    .menu {
    }
    .trig {
        padding : 10px ;
    }
</style>
<table class=fence border=0 cellpadding=0 cellspacing=0>
  <tr>
    <td colspan=2>
    <table class=topcontent border=0 cellpadding=0 cellspacing=0>
      <tr>
	<td valign=top width=50%>
	  <?php include("sysinfo.php"); ?>
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
    <td class=rightcontent>
      <?php 
	  /* 
	   * this is the right side of the page. it will contain some
	   * iframes to include the time range the page refers to (netview)
	   * 
	   * XXX  This is a config option now
	   * 
	   */


          $sec_array = $node -> GetConfigModules 
                                ($comonode, "secondary");
          $interval=$etime-$stime;
          for ($i=1;$i<count($sec_array);$i++) {
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
		$modargs = $modargs . "topn=5&";
		$modargs = $modargs . "url=generic_query.php&";
		$modargs = $modargs . "urlargs=stime=$stime&";
		$modargs = $modargs . "urlargs=etime=$etime&";
		$modargs = $modargs . "urlargs=interval=$interval&";
		$modargs = $modargs . "urlargs=module=tuple&";
		$modargs = $modargs . "urlargs=source=tuple&";
		$modargs = $modargs . "urlargs=format=plain&";
		$modargs = $modargs . "urlargs=extra=blincview&";
	      }
	      if ($sec_array[$i] == "topports"){
		$modargs = "filter={$node->modinfo[$sec_array[$i]]['filter']}&";
		$modargs = $modargs . "topn=5&";
		$modargs = $modargs . "source=tuple&";
		$modargs = $modargs . "interval=$interval&";
	      }
              print "<div class=menubar>";
	      print "<a href=# id=$sec_array[$i]Trig class=trig>";
              print "$sec_array[$i]</a>";

              print "<div id=$sec_array[$i]Menu class=menu>";
	      print "<iframe width=100% frameborder=0 ";
	      print "src=generic_query.php?comonode=$comonode&";
	      print "module={$sec_array[$i]}&format=html&";
	      print "stime=$stime&etime=$etime&";
	      print "$modargs";
	      print "urlargs=comonode=$comonode&";
#	      print "urlargs=module=$module&";
	      print "urlargs=filter={$node->modinfo[$sec_array[$i]]['filter']}>";
	      print "</iframe>";
              print "</div>";
              print "</div>\n";
	  }
      ?>
    </td>
  </tr>
</table>

<?php
    include("include/footer.php.inc");
?>
