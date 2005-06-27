<!-- $Id$ --> 

<html>

<?php 

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
    include("comolive.conf");
    $level = "top"; 
    include("include/menulist.php");
    ?>
    <div id=content>
      <div class=graph onmouseover="javascript:clearmenu('smenu')">
	<br><br><center>
        CoMo node <?= $host ?> cannot be contacted. <br>
	Please try another time.
      </div>
    </div>
    <?php include("include/footer.php"); ?>
    <?php
    exit;
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
        $delay = ((int) strtok(":\n")) * 2;
    $tok = strtok(":\n");
}

/* banner on top */
include("include/header.php"); 

/* read configuration parameters */
include("comolive.conf");

/* run the query and generate the resulting image and update 
 * the php_env file that flash will fetch. Note that 
 * XXX the variable $filename will contain the image */
include("include/query.php");

$level = "system"; 
include("include/menulist.php");

include ("include/vcrbuttons.php"); 
?>

<div id=content>
  <div class=graph>
    <br>
    <?php 
	if ($USEFLASH == false) 
 	    print "<img src=$filename.jpg>";
	else 
	    include("flash/zoom.html");
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
      if (!is_null($comment)) 
	  print "Notes: $comment<br>";
?>
      <br>

<?php /*
    <div class=title>Status Information</div>
      Active modules: <?= $active_modules ?><br>
      Loaded modules: <?= $total_modules ?><br>

    <div class=title>Traffic Load (Mbps)</div>
      5 minutes average: <?= $mbps_5min ?><br>
      1 hour average: <?= $mbps_1hr ?><br>
      24 hours average: <?= $mbps_24hrs ?><br>
      Link Speed: <?= $linkspeed ?><br>
*/ ?>
      
    <div class=title>Image Info</div>
      <!-- Module: <?= $mdl ?><br> -->
      Time interval:<br>
	<?php 
	    $startstr = strftime("%a %b %d %T %Y", $stime - 3600); 
	    $endstr = strftime("%a %b %d %T %Y", $etime - 3600); 
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
	print "&filter=ALL";
    print "&stime=$hr&etime=$sec\">\n";
    print "View last hour</a><br>\n"; 

    print "<a href=\"system.php?node=$host&module=$mdl";
    if (!is_null($filter))
	print "&filter=$filter";
    else
	print "&filter=ALL";
    print "&stime=$day&etime=$sec\">\n";
    print "View last 24 hours</a><br>\n"; 

    print "<a href=\"system.php?node=$host&module=$mdl";
    if (!is_null($filter))
	print "&filter=$filter";
    else
	print "&filter=ALL";
    print "&stime=$week&etime=$sec\">\n";
    print "View last week</a><br>\n"; 

?>
    <br>

  </div>
</div>

<?php include("include/footer.php"); ?>
</body>
</html>



