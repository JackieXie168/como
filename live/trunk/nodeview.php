<?
/*  nodeview.php 
 * 
 *  This file will require the comonode=host:port arg passed to it  
 *  <!-- $Id$  -->
 */
  require_once("comolive.conf");
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

    if (isset($_GET['groupname']) && $_GET['groupname'] != "")
        $groupname = $_GET['groupname'];
    else
        $groupname = "default";


    if ($method == "Submit") {
#	$includebanner=1; 
#	include("include/header.php.inc");
	if (isset($_GET['groupselect']))
	    $groupselect = $_GET['groupselect'];
	if (isset($_GET['nodename']))
	    $nodename= $_GET['nodename'];
	if (isset($_GET['nodeplace']))
	    $nodeplace = $_GET['nodeplace'];
	if (isset($_GET['speed']))
	    $speed = $_GET['speed'];
	if (isset($_GET['comment']))
	    $comment = $_GET['comment'];

        /*  Create the default file  */
        if ($groupselect == "default") {
            $groupselect = "default.lst";
            if (!file_exists("$NODEDB/$groupselect")) {
		$fh = fopen ("$NODEDB/$groupselect", "w");
		$towrite = "CoMo Nodes\n";
		fwrite ($fh, $towrite);
		fclose($fh);
            }
        }
	$tmp = file ("$NODEDB/$groupselect");
	$numlines = count($tmp);
        if ($numlines == 1) {
	    $fh = fopen("$NODEDB/$groupselect", "a");
	    $tofile = "Name;;CoMo Name:Port;;Location;;Interface;;Comments;;\n";
	    if (fwrite ($fh, $tofile) === FALSE){
		print "$NODEDB/$groupselect not writable";
		exit;
	    }
	    fclose($fh);
        }
	$fh = fopen("$NODEDB/$groupselect", "a");

        $tofile = $nodename . ";;" ;
        $tofile = $tofile . $comonode . ";;" ;
        $tofile = $tofile . $nodeplace . ";;" ;
        $tofile = $tofile . $speed . ";;" ;
        $tofile = $tofile . $comment . ";;\n" ;

	if (fwrite ($fh, $tofile) === FALSE) {
	    header ("Location: nodeview.php?comonode=$comonode&status=fail");
	} else {
	    header ("Location: index.php");
	}
	fclose($fh);
    }
    if ($method == "Add Group"){
	$groupfname = ereg_replace (" ", "_", $groupname);
        if (!file_exists("$NODEDB/$groupfname")) {
	    if ($fh = fopen ("$NODEDB/$groupfname.lst", "w")) {
		$towrite = "$groupname\n";
		fwrite ($fh, $towrite);
		header ("Location: nodeview.php?comonode=$comonode");
		exit;
	    } else {
		print "Unable to open file $NODEDB/$group for writing";
	    }
	}
    }
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
        /*  get the groups */
	$dadir = $NODEDB;
	$handle=opendir("$dadir");
	$allgroups=array();
        $x=0;
	while (false!==($filez= readdir($handle))) {
	   if ($filez!= "." && $filez!= ".." && ereg (".*\.lst$", $filez)) {
               if (file_exists("$NODEDB/$filez")) {
		   $desc = file ("$NODEDB/$filez");
		   $allgroups[$x][0] = $filez;
		   $allgroups[$x][1] = $desc[0];
                   $x++;
               }
	   }
	}
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

  <body>
  <object>
  <div class="sysinfobar">
    <form action="nodeview.php" method="GET">
    <table border=0><tr><td>
    <table class=sysinfo border=0>
      <tr> <td> <div class=title>Group name</div> </td> </tr>
      <tr>
        <td> 
            <select size=1 name=groupselect>
              <option value=default selected>Group
            <?
              for ($i=0;$i<count($allgroups);$i++) {
                  print "<option value={$allgroups[$i][0]}>";
                  print "{$allgroups[$i][1]}";
              }
            ?>
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
    </td><td valign=top>
    <form action="nodeview.php" method="GET">
    <table border=0>
      <tr> <td> <div class=title>Add a new group name</div> </td> </tr>
      <tr> <td> <input type=textbox name=groupname></td> </tr>
      <tr> <td> <input type=submit name=method value="Add Group"></td> </tr>
    </table>
    </form>
    </td></tr></table>
  </div>
  </form>
  </object>
  </body>
</html>
<?
    include("include/footer.php.inc");
    }
?>
