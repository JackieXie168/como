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
	      src=mainstage.php?<?=$_SERVER['QUERY_STRING']?>>
      </iframe>
    <td class=rightcontent>
      <?php 
	  /* 
	   * this is the right side of the page. it will contain three 
	   * iframes to include the time range the page refers to (netview)
	   * and three other queries to the CoMo system.
	   * 
	   * XXX right now the queries are hard coded and will be "alert", 
	   *     "topdest" and "topports". 
	   * 
	   */
          $interval=$etime-$stime;
	
          print "<iframe width=100% frameborder=0 ";
          print "src=generic_query.php?comonode=$comonode&";
          print "module=alert&format=html&";
 	  print "&stime=$stime&etime=$etime&url=dashboard.php&";
          print "urlargs=comonode=$comonode&";
	  print "urlargs=module=$module&";
	  if ($module == $special) {
	      print "urlargs=source=tuple&urlargs=interval=$interval&";
	  }
	  print "urlargs=filter={$node->loadedmodule[$module]}>";
          print "</iframe>\n";

      	  print "<iframe width=100% frameborder=0 "; 
          print "src=generic_query.php?comonode=$comonode&";
          print "module=topdest&format=html&";
	  print "filter=ip&topn=5&source=tuple&interval=$interval";
 	  print "&stime=$stime&etime=$etime&url=broadcast.php&";
	  print "urlargs=stime=$stime&urlargs=etime=$etime&";
	  print "urlargs=module=$module&";
	  print "urlargs=filter={$node->loadedmodule[$module]}>";
          print "</iframe>\n";

      	  print "<iframe width=100% height=150 frameborder=0 "; 
          print "src=generic_query.php?comonode=$comonode&";
          print "module=topports&format=html&";
	  print "filter=tcp%20or%20udp&topn=5&source=tuple&interval=$interval";
 	  print "&stime=$stime&etime=$etime&url=broadcast.php&";
	  print "urlargs=stime=$stime&urlargs=etime=$etime&";
	  print "urlargs=module=$module&";
	  print "urlargs=filter={$node->loadedmodule[$module]}>";
          print "</iframe>\n";
      ?>
    </td>
  </tr>
</table>

<?php
    include("include/footer.php.inc");
?>
