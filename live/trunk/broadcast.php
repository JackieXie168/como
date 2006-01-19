<?php
include ("include/header.php.inc");
include ("class/node.class.php");
include ("class/query.class.php");
include ("comolive.conf");

/*  get the node hostname and port number */
#if (isset($_GET['comonode'])) {
#    $comonode = $_GET['comonode'];
#} else {
#    print "sysinfo.php requires the comonode=host:port arg passed to it";
#    exit;
#}

#$node = new Node($comonode, $TIMEPERIOD, $TIMEBOUND);
#
# GET input variables
#
include ("include/getinputvars.php.inc");

$startstr = gmstrftime("%a %b %d %T %Y", $stime);
$endstr = gmstrftime("%a %b %d %T %Y", $etime);
$duration = $etime - $stime;

?>
<html>
  <head>
    <style type="text/css">
      .sysinfobar{
        color :#FFF;
        width :100%;
        padding :2px;
        text-align:center;
      }
      .sysinfo {
        top: 0px;
        width: 80%;
        background-color: #FFF;
        margin: 2;
        padding-left: 5px;
        padding-right: 5px;
        font-size: 9pt;
        text-align:left;
      }
      .title {
        font-weight: bold;
        font-size: 9pt;
        padding-bottom: 3px;
        color: #475677;
      }
    </style>

  </head>

   <body>
    <script language="JavaScript">
    <!--
      window.resizeTo(600,900);
    -->
    </script>
<?

/*  Read the list of nodes to query  */
$list = array();

/*  XXX Need to handle this better  */
$dafile = file("$NODEDB/nodes.lst");

for ($i = 1; $i < count($dafile); $i++) {
    $daline = explode(";;", $dafile[$i]);
    array_push($list, $daline[1]);
}

$query = new Query ($stime, $etime, $RESULTS, $GNUPLOT, $CONVERT, $RESOLUTION);
$query_plot = $query->get_query_string($module, $format, "filter=$filter"); 

$counter_str = "filter=dst $ip&interval=$duration&source=tuple&granularity=1";
$query_counter = $query->get_query_string("traffic", "mbps", $counter_str);  

for ($i=0;$i<count($list);$i++){
    $node = new Node($list[$i], $TIMEPERIOD, $TIMEBOUND);
    if ($node->status == "OK"){
        $data = $query->do_query($node->comonode, $query_plot);
        $filename = $query->plot_query($data[1], $node->comonode, $module);
	if (!file_exists("${filename}.jpg"))
	    continue; 
	$mbps = $query->do_query($node->comonode, $query_counter); 
	if ($mbps[0] == 0)
	    $mbps[1] = 0; 
        ?>
        <center>
        <table>
          <tr valign=top>
            <td>
              <div class=title>Location</div>
              <?= $node->nodename ?><br>
              <?= $node->nodeplace ?><br>
              <div class=title>Host</div>
              <? print "$ip<br>"; ?>
              <div class=title>Traffic</div>
              <? print "$mbps[1]<br>"; ?>
              <div class=title>Time Interval</div>
              <?= $startstr?><br>
              <?= $endstr?><br>
              <?= $duration?> sec<br>
            </td>
            <td>
               <a href="#" onClick="return MyWindow=window.open('singleview.php?filename=<?=$filename?>&nodename=<?=$node->nodename?>&nodeplace=<?=$node->nodeplace?>&module=<?=$module?>&stime=<?=$stime?>&etime=<?=$etime?>', 'MyWindow', 'toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=no,resizeable=yes,width=620,height=550');return false;"><img width=300 src="<?=$filename?>.jpg"></a>
            </td>
          </tr>
        </table> 
        <center>
       <? 
    }
}



include ("include/footer.php.inc");
?>
