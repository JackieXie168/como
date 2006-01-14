<!-- $Id$  -->
<?
/*  nodeview.php 
 * 
 *  This file will require the comonode=host:port arg passed to it  
 */
require_once("comolive.conf");
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
      .title1 {
	font-weight: bold;
	font-size: 14pt;
	padding-bottom: 3px;
	color: #475677;
      }
    </style>
  </head>

  <?php
  /*  get the node hostname and port number */
    if (isset($_GET['comonode'])){
        $comonode = $_GET['comonode'];
    }else{
        print "This file requires the comonode=host:port arg passed to it";
        exit;
    }

    if (isset($_GET['method']))
        $method = $_GET['method'];
    else
        $method = "addnode";

    if ($method == "addnode") {

        $includebanner=1; 
	include("include/header.php.inc");
	include ("class/node.class.php");
        /*  Query the CoMo node  */
        $node = new Node($comonode,$TIMEPERIOD, $TIMEBOUND);
        if ($node->status == "FAIL"){
        /*
	 * query failed. write error message and exit
	 */
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
	?>
  <body>
  <object>
  <div class="sysinfobar">
    <form method="nodeview.php" method="GET" name=method>
    <table class=sysinfo border=0>
      <tr>
	<td> <div class=title1>Select the region for you new node</div> </td>
      </tr>
      <tr>
	<td> <div class=title>Region</div> </td>
      </tr>
      <tr>
        <td> <select name=region>
             <!--<option selected value="">Select a Region</option>-->
             <option selected value="europe">Europe</option>
             <option value="northamerica">North America</option>
             <option value="southamerica">South America</option>
             <option value="asia">Asia</option>
             <option value="africa">Africa</option>
             <option value="oceania">Oceania</option>
             <option value="other">Other</option>
             </select>
      </tr>
      <tr>
	<td> <div class=title>Como Node </div> </td>
      </tr>
      <tr>
	<td><?=$node->comonode?></td> </tr>
      <input type=hidden name=comonode value="<?=$node->comonode?>">
      <tr> <td> <div class=title>Node Name</div> </td> </tr>
      <tr> <td><?= $node->nodename ?></td> </tr>
      <input type=hidden name=nodename value="<?=$node->nodename?>">
      <tr> <td> <div class=title>Location</div> </td> </tr>
      <tr> <td><?= $node->nodeplace ?></td> </tr>
      <input type=hidden name=nodeplace value="<?=$node->nodeplace?>">
      <tr> <td> <div class=title>Interface</div> </td> </tr>
      <tr><td > <?= $node->linkspeed ?></td></tr>
      <input type=hidden name=speed value="<?=$node->linkspeed?>">
      <tr> <td> <div class=title>Data Source</div> </td> </tr>
      <tr> <td> <?= $node->comment ?></td> </tr>
      <input type=hidden name=comment value="<?=$node->comment?>">
      <tr> <td> <input type="submit" name=method value="Submit"> </td> </tr>
    </table>
  </div>
  </form>
  <?php
  } 
  if ($method == "Submit") {
    $includebanner=1; 
    include("include/header.php.inc");
    if (isset($_GET['region']))
	$region = $_GET['region'];
    if (isset($_GET['nodename']))
        $nodename= $_GET['nodename'];
    if (isset($_GET['nodeplace']))
        $nodeplace = $_GET['nodeplace'];
    if (isset($_GET['speed']))
        $speed = $_GET['speed'];
    if (isset($_GET['comment']))
        $comment = $_GET['comment'];
    
    if (!(file_exists("$NODEDB/$region.lst"))){
	if (!($fh = fopen("$NODEDB/$region.lst", "w"))){
            print "Unable to open file $NODEDB/$region.lst";
            exit;
        }
        $tofile = $region . "\n ;Name;Location;Interface;Data Source;\n";
        if (fwrite ($fh, $tofile) === FALSE){
            print "$NODEDB/$region.lst not writable";
            exit;
        }
	fclose($fh);
    }

    $fh = fopen("$NODEDB/$region.lst", "a");

    $tofile = $comonode . ";" . $nodename . ";" . $nodeplace . ";" . $speed . ";" . $comment. "\n" ;
    if (fwrite ($fh, $tofile) === FALSE)
        print "data was not written to file";
    else{
        print "Data was successfully written to $NODEDB/$region.lst<br>";
        print "<a href=index.php > Back to main</a>";
    }
    fclose($fh);
  }
include("include/footer.php.inc");
  ?>
  </object>
  </body>
</html>
