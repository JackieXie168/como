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
    $node = new Node($comonode, $TIMEPERIOD, $TIMEBOUND);
    /*
    * GET input variables
    */
    $special = "ports";
    include("include/getinputvars.php.inc");
?>

<body>
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
                                ($comonode, $NODEDB, "secondary");
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
	      }
	      if ($sec_array[$i] == "topports"){
		$modargs = "filter={$node->modinfo[$sec_array[$i]]['filter']}&";
		$modargs = $modargs . "topn=5&";
		$modargs = $modargs . "source=tuple&";
		$modargs = $modargs . "interval=$interval&";
	      }
	      print "<iframe width=100% frameborder=0 ";
	      print "src=generic_query.php?comonode=$comonode&";
	      print "module={$sec_array[$i]}&format=html&";
	      print "stime=$stime&etime=$etime&";
	      print "$modargs";
	      print "urlargs=comonode=$comonode&";
#	      print "urlargs=module=$module&";
	      print "urlargs=filter={$node->modinfo[$sec_array[$i]]['filter']}>";
	      print "</iframe>\n";
	  }
#	
#          print "<iframe width=100% frameborder=0 ";
#          print "src=generic_query.php?comonode=$comonode&";
#          print "module=alert&format=html&";
# 	  print "&stime=$stime&etime=$etime&url=dashboard.php&";
#          print "urlargs=comonode=$comonode&";
#	  print "urlargs=module=$module&";
#	  if ($module == $special) {
#	      print "urlargs=source=tuple&urlargs=interval=$interval&";
#	  }
#	  print "urlargs=filter={$node->loadedmodule[$module]}>";
#          print "</iframe>\n";
#
#      	  print "<iframe width=100% frameborder=0 "; 
#          print "src=generic_query.php?comonode=$comonode&";
#          print "module=topdest&format=html&";
#	  print "filter=ip&topn=5&source=tuple&interval=$interval";
# 	  print "&stime=$stime&etime=$etime&url=broadcast.php&";
#	  print "urlargs=stime=$stime&urlargs=etime=$etime&";
#	  print "urlargs=module=$module&";
#	  print "urlargs=filter={$node->loadedmodule[$module]}>";
#          print "</iframe>\n";
#
#      	  print "<iframe width=100% height=150 frameborder=0 "; 
#          print "src=generic_query.php?comonode=$comonode&";
#          print "module=topports&format=html&";
#	  print "filter=tcp%20or%20udp&topn=5&source=tuple&interval=$interval";
# 	  print "&stime=$stime&etime=$etime&url=broadcast.php&";
#	  print "urlargs=stime=$stime&urlargs=etime=$etime&";
#	  print "urlargs=module=$module&";
#	  print "urlargs=filter={$node->loadedmodule[$module]}>";
#          print "</iframe>\n";
      ?>
    </td>
  </tr>
</table>

<?php
    include("include/footer.php.inc");
?>
