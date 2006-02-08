<!--  $Id$  -->

<?php
    /* 
     * this is the entry page to the CoMolive! site. show the banner
     * and add the usual html header stuff. 
     */
    $includebanner=1;
    include("include/header.php.inc");
    include("comolive.conf");
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
<script>
    function clearText(thefield){
    if (thefield.defaultValue==thefield.value)
        thefield.value = ""
    }
</script>
<style>
    .nodeselect {
	width:40%;
	text-align:center;
	left:10px;
	padding-left:5px;
	padding-right:5px;
    }
    .leftmain {
	width:70%;
	vertical-align:top
	padding:10px;
    }
    .grouphead {
        font-size : 20px;
        font-weight : bold;
        background-color : #EEE;
    }
    .grouplink{
        font-size : 10px;
        display : inline;
    }

</style>
<body>
<table class=fence>
  <tr>
    <td class=leftmain>

<?php
$numgroup = count($allgroups);
if ($numgroup < 1) {
    print "<div class=grouphead>CoMo Nodes</div>";
    print "no como nodes saved";
} else { 
    for ($i=0;$i<count($allgroups);$i++) {
	$nodefile = "$NODEDB/{$allgroups[$i][0]}";
        $numlines = count(file ("$nodefile"));
        if ($numlines <= 2) {
	    print "<div class=grouphead>{$allgroups[$i][1]}";
	    print "<a href=managenode.php?action=groupdel";
	    print "&group={$allgroups[$i][0]}";
	    print "&comonode=blank:44444>";
            if ($ALLOWCUSTOMIZE) {
		print "<div class=grouplink>Remove</a>";
		print "</div>";
            }

            print "</div>";
	    print "no como nodes saved";
         
        } else {
	    if ($fp = fopen ("$nodefile", "r")) {
		print "<table cellpadding=0 cellspacing=2>";
		while (!feof($fp)) {
		    $line = fgets($fp);
		    if ($line == $allgroups[$i][1]) {
			print "<div class=grouphead>{$allgroups[$i][1]}";
			if ($ALLOWCUSTOMIZE) {
			print "<a href=managenode.php?action=groupdel";
			print "&group={$allgroups[$i][0]}";
			print "&comonode=blank:44444>";
			    print "<div class=grouplink>Remove</a>";
			    print "</div>";
                        }
                        print "</div>";
 
                    } 
		    if (($line != "") && ($line != $allgroups[$i][1])) {
			list($name, $comonode, $loc, $iface, $comment) 
			    = split(';;', $line);
                        list ($host, $port) = split (":", $comonode);
			print "<tr>";
			print "<td width=200 valign=top>";
			if ($name != "Name") {
			    print "<a href=dashboard.php?comonode=$comonode>";
			    print "$name</a>";
			} else {
			    print "$name";
			}
			print "</td>";
			print "<td width=100 valign=top>$port</td>";
			print "<td width=150 valign=top>$loc</td>";
			print "<td width=150 valign=top>$iface</td>";
			print "<td width=500 valign=top>$comment</td>";
			if ($name != "Name" && $ALLOWCUSTOMIZE) {
			    print "<td valign=top align=right>";
			    print "<a href=managenode.php?action=delete";
			    print "&comonode=$comonode";
                            print "&group={$allgroups[$i][0]}>";
                            print "Remove</a></td>";
			} 
			print "</tr>";
		    }
		}
	    }
        print "</table>";

        }
    }
}
    ?>
    </td>
    <td class=nodeselect valign=top>
      Select node by IP address
      <form align=middle action=dashboard.php method=get>
	<input type=text name=comonode size=21 value="comonode:44444"
         onFocus=clearText(this);>
	<input type=image src=images/go.jpg>
      </form>

    <?  if ($ALLOWCUSTOMIZE) { ?>
      <br>
      Add a new CoMo node
      <form align=middle action=nodeview.php method=get>
	<input type=text name=comonode size=21 value="comonode:44444"
         onFocus=clearText(this);>
	<input type=image src=images/go.jpg >
      </form>
    <? } ?>
    </td>
  </tr>
</table>
</body>


<?php
    include("include/footer.php.inc");
?>


