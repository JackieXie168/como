<?php
if (isset($_GET['filename']))
    $filename = $_GET['filename'];
if (isset($_GET['nodename']))
    $nodename = $_GET['nodename'];
if (isset($_GET['nodeplace']))
    $nodeplace = $_GET['nodeplace'];
if (isset($_GET['module']))
    $module = $_GET['module'];
if (isset($_GET['start']))
    $start = $_GET['start'];
if (isset($_GET['end']))
    $end = $_GET['end'];

$startstr = gmstrftime("%a %b %d %T %Y", $start);
$endstr = gmstrftime("%a %b %d %T %Y", $end);
$duration = $end - $start;
$days = floor($duration / 86400);
$hours = floor(($duration % 86400) / 3600);
$mins = floor(($duration % 3600) / 60);
$secs = $duration % 60;

?>


<html>
  <head> 
   <title><?=$nodename?> <?=$nodeplace?></title>
   <link rel="stylesheet" type="text/css" name="como" href="css/comolive.css"> 
  </head>
   <body>
     <center>
       <?

       print "Node: $nodename<br>";
       print "Location: $nodeplace<br>";
       print "Interval:<br>";
       print " $startstr<br>";
       print " $endstr<br>";
       print "&nbsp; [${days}d ${hours}h ${mins}m ${secs}s]<br>\n";
       print "<img src=$filename.jpg>";
       ?>
     </center>
   </body>

</html>
