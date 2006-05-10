<!--  $Id$  -->
<?
    /* 
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
	width: 100%;
        vertical-align:top;
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
      .seperator {
        padding-left : 12px;
        border-left : 1px solid grey;
      }
      .customize {
	font-weight: bold;
	font-size: 9pt;
	color: #d71e48;
      }
    </style>
  </head>

<?
    /* get the node hostname and port number */
    if (isset($_GET['comonode'])) {
      $comonode = $_GET['comonode'];
      $comonode_array = split (";;", $comonode);
      $comonode = $comonode_array[0];
    } else {
      print "{$_SERVER['SCRIPT_FILENAME']}";
      print " requires the comonode=host:port arg passed to it";
      exit;
    }

    require_once ("class/node.class.php");
    /*  Query the CoMo node  */

    $node = new Node($comonode,$TIMEPERIOD, $TIMEBOUND);
    if ($node->status == "FAIL") {
	/*
	 * query failed. write error message and exit
	 */
	include("include/header.php.inc");
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
#	exit;
    }
?>

  <body>
  <object>
  <div class="sysinfobar">
    <table class=sysinfo>
      <tr valign=top>
	<td valign=top class=seperator>
	    <div class=title>Location</div>
	    <?= $node->nodename ?><br>
	    <?= $node->nodeplace ?><br>
            <?  if ($ALLOWCUSTOMIZE) { ?>
            <a href="#" onClick="return customize=window.open('customize.php?comonode=<?=$comonode?>','customize','width=700,height=450,status=no'); return false;">
	    <div class=customize>Customize CoMoLive!</div>
            </a>
            <? } ?>
	</td>
	<td class=seperator>
	  <div class=title>System Information</div>
	  Software: <?= $node->version ?><br>
          Online Since: <?= gmstrftime("%a %b %d %T %Y", $node->start);?><br>
	  Built: <?= $node->builddate ?>

	</td>
        <?
	if (isset($comment) && (!is_null($comment))){
          print "<td><div class=title>Notes:</div>";
          print "$comment<br></td>";
        }?>
      </tr>
    </table>
  </div>
  <?php
  /*
    <div class=title>Status Information</div>
      Active modules: <?= $active_modules ?><br>
      Loaded modules: <?= $total_modules ?><br>

  */
  #$node->PrintDebug();
  ?>
  </object>
  </body>
</html>
