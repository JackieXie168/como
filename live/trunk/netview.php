<!--  $Id$  -->
<?php
    require_once("comolive.conf");
    $startstr = gmstrftime("%a %b %d %T %Y", $stime);
    $endstr = gmstrftime("%a %b %d %T %Y", $etime);
    /*  Remove this section as soon as distquery is a como module  */
    if ($module == "distquery") 
        $module = "traffic";
    /*  End remove  */
    $firstpacket = gmstrftime("%a %b %d %T %Y", $node->modinfo[$module]['stime']);
    $duration = $etime - $stime;
    $days = floor($duration / 86400); 
    $hours = floor(($duration % 86400) / 3600);
    $mins = floor(($duration % 3600) / 60); 
    $secs = $duration % 60; 
?>
<html>
  <head>
    <style type="text/css">
      .netviewbar{
        color :#FFF;
        width :100%;
        text-align:right;
      }
      .netview {
        top: 0px;
        width: 100%;
        vertical-align:top;
        background-color: #FFF;
        margin: 2;
        padding-left: 5px;
        padding-right: 5px;
        font-size: 9pt;
        text-align:left;
      }
      .nvtitle {
        font-weight: bold;
        font-size: 9pt;
        padding-bottom: 3px;
        color: #475677;
      }
      .seperator {
          padding-left : 12px;
          border-left : 1px solid grey;
      }

    </style>
  </head>
  <body>
<div class=netviewbar>
<table class=netview>
  <tr valign=top>
    <td class=seperator>
    <div class=nvtitle>Current Network View</div>
      Time interval (UTC):<br>
        <?php
            print "&nbsp; $startstr<br>\n";
            print "&nbsp; $endstr<br>\n"; 
	    print "&nbsp; [${days}d ${hours}h ${mins}m ${secs}s]<br>\n"; 
        ?>
      </td>
      <td class=seperator>
    <div class=nvtitle>Controls</div>
<?php
    include("include/vcrbuttons.php.inc");
    $sec = $node->etime;

    $hr = $sec - 3600;
    $day = $sec - 86400;
    $week = $sec - 86400*7;
    $month = $sec - 30*86400*7;

    print "<a href=\"dashboard.php?comonode=$comonode&module=$module&";
#    if ($module == $special) {
#	$interval = $sec - $hr; 
#        print "source=tuple&interval=$interval&";
#    }
    if (!is_null($filter))
        print "filter=$filter&";
    else
        print "filter=all&";
    print "stime=$hr&etime=$sec\">\n";
    print "View last hour</a><br>\n";

    print "<a href=\"dashboard.php?comonode=$comonode&module=$module";
#    if ($module == $special) {
#	$interval = $sec - $day; 
#        print "&source=tuple&interval=$interval";
#    }
    if (!is_null($filter))
        print "&filter=$filter";
    else
        print "&filter=all";
    print "&stime=$day&etime=$sec\">\n";
    print "View last 24 hours</a><br>\n";

    print "<a href=\"dashboard.php?comonode=$comonode&module=$module";
#    if ($module == $special) {
#	$interval = $sec - $week; 
#        print "&source=tuple&interval=$interval";
#    }
    if (!is_null($filter))
        print "&filter=$filter";
    else
        print "&filter=all";
    print "&stime=$week&etime=$sec\">\n";
    print "View last week</a><br>\n";

?>
  </tr>
</table>
</div>
</html>
