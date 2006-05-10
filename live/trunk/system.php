<!-- $Id$ --> 

<html>

<?php 

include("comolive.conf");

/* get the node hostname and port number */
$host = $_GET['node'];
$nodename = NULL;

/* 
 * query the node to get statistics and other
 * up-to-date information (e.g., which modules are running, etc.)
 *
 * XXX we are doing this every time this page is loaded. it would be
 *     better to store this information somewhere on the client as long
 *     as the client is interested to the same CoMo node. However, we 
 *     would guess the delay value... 
 */
$nodeinfo = file_get_contents("http://$host/?status");
if ($nodeinfo == false) {
    /*
     * query failed. write error message and exit
     */
    include("include/header.php"); 
    $level = "top"; 
    include("include/menulist.php");
    ?>
    <div id=content>
      <div class=graph onmouseover="javascript:clearmenu('smenu')">
	<br><br><center>
        Sorry but the requested CoMo node is not <br>
	available at the moment. Please try another time.
      </div>
    </div>
    <?php include("include/footer.php"); ?>
    <?php
#    exit;
}

/* parse the node information */
$tok = strtok($nodeinfo, ":\n");
while ($tok !== false) {
    if ($tok === "Name")
        $nodename = strtok(":\n");
    else if ($tok === "Location")
        $nodeplace = strtok(":\n");
    else if ($tok === "Comment")
        $comment = strtok(":\n");
    else if ($tok === "Speed")
        $linkspeed = strtok(":\n");
    else if ($tok === "Version")
        $version = strtok(":\n");
    else if ($tok === "Build date")
        $builddate = strtok(":\n");
    else if ($tok === "Delay")
        $delay = ((int) strtok(":\n")); 
    $tok = strtok(":\n");
}

/* banner on top */
include("include/header.php"); 

/*
 * first of all, parse the input variables.
 * this file will give us the following variables:
 *   . module name (mdl)
 *   . filter expression (filter)
 *   . start time (stime) aligned to $GRANULARITY (see comolive.conf)
 *   . end time (etime) aligned to $GRANULARITY (see comolive.conf)
 */
include ("include/variables.php");

$level = "system"; 
include("include/menulist.php");

include ("include/vcrbuttons.php"); 

?>

<div id=content>
  <div class=graph>
    <br>
    <?php 
	/* run the query and generate the resulting image 
	 * XXX the variable $filename will contain the image */
	include("include/query.php");
    ?> 

  </div>

  <div class=sysinfo onmouseover="javascript:clearmenu('smenu')">
    <div class=title>Location</div>
      <?= $nodename ?><br>
      <?= $nodeplace ?><br>
      <br>

    <div class=title>System Information</div>
      Software: <?= $version ?><br>
      Built: <?= $builddate ?><br>
<?php
      if ($delay > 60) {
	  $dmin = floor($delay / 60); 
	  print "Delay: $dmin minutes<br>"; 
      }
      if (isset($comment) && (!is_null($comment))) 
	  print "Notes: $comment<br>";
?>
      <br>

<?php 
/*
    <div class=title>Status Information</div>
      Active modules: <?= $active_modules ?><br>

    <div class=title>Traffic Load (Mbps)</div>
      Past 5 minutes: <?= $mbps_5min ?><br>
      Past hour: <?= $mbps_1hr ?><br>
      Past 24 hours: <?= $mbps_24hrs ?><br>
      Link Speed: <?= $linkspeed ?><br>
*/ 
?>
      
    <div class=title>Image Info</div>
      Time interval (UTC):<br>
	<?php 
	    $startstr = gmstrftime("%a %b %d %T %Y", $stime); 
	    $endstr = gmstrftime("%a %b %d %T %Y", $etime); 
	    print "&nbsp; $startstr<br>&nbsp; $endstr<br>";
	?>
      Download: [<a href=<?=$filename?>.jpg>JPG</a>]
                [<a href=<?=$filename?>.eps>EPS</a>]<br>
      <br>

    <div class=title>Controls</div>
<?php 

    $now = gettimeofday();
    $now["sec"] -= $delay;
    $sec = $now["sec"];

    $hr = $now["sec"] - 3600; 
    $day = $now["sec"] - 86400; 
    $week = $now["sec"] - 86400*7; 
    $month = $now["sec"] - 30*86400*7;

    print "<a href=\"system.php?node=$host&module=$mdl";
    if (!is_null($filter))
	print "&filter=$filter";
    else
	print "&filter=all";
    print "&stime=$hr&etime=$sec\">\n";
    print "View last hour</a><br>\n"; 

    print "<a href=\"system.php?node=$host&module=$mdl";
    if (!is_null($filter))
	print "&filter=$filter";
    else
	print "&filter=all";
    print "&stime=$day&etime=$sec\">\n";
    print "View last 24 hours</a><br>\n"; 

    print "<a href=\"system.php?node=$host&module=$mdl";
    if (!is_null($filter))
	print "&filter=$filter";
    else
	print "&filter=all";
    print "&stime=$week&etime=$sec\">\n";
    print "View last week</a><br>\n"; 

?>
    <br>

  </div>
</div>

<?php include("include/footer.php"); ?>
</body>
</html>



