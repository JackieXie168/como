<!--  $Id$  -->

<?php
    /* 
     * this is the entry page to the CoMolive! site. show the banner
     * and add the usual html header stuff. 
     */
    $includebanner=1;
    include("include/header.php.inc");
    include("comolive.conf");
    $nodefile = "$NODEDB/nodes.lst";
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
</style>
<body>
<table class=fence>
  <tr>
    <td class=leftcontent>
      <h2>Como Nodes</h2>
    <?php
        if (!file_exists($nodefile)) {
            print "no como nodes saved";
        } else {
            if ($fp = fopen ($nodefile, "r")) {
		print "<table cellpadding=0 cellspacing=0 border=0>";
		while (!feof($fp)) {
		    $line = fgets($fp);
		    if ($line != ""){
			list($comonode, $loc, $iface, $comment) = split(';', $line);
                        list ($name, $port) = split (":", $comonode);
			print "<tr>";
			print "<td width=200>";
		    if ($name != "Node Name")
			print "<a href=dashboard.php?comonode=$comonode>$name</a>";
		    else
			print "$name";

		    print "</td>";
		    print "<td width=250>$port</td>";
		    print "<td width=250>$loc</td>";
		    print "<td width=150>$iface</td>";
		    print "<td width=400>$comment</td>";
		    if ($name != "Node Name")
			print "<td><a href=managenode.php?action=delete&comonode=$name:$port>Remove</a></td>";
                    else 
			print "<td width=200>&nbsp;<td>";
		    print "</tr>";
            }
        }
        print "</table>";

            } else {
                print "unable to open the file $nodefile<br>";
            }
        }

    ?>
    </td>
    <td class=nodeselect>
      Select node by IP address
      <form align=middle action=dashboard.php method=get>
	<input type=text name=comonode size=21 value="comonode:44444"
         onFocus=clearText(this);>
	<input type=image src=images/go.jpg>
      </form>
      <br>
      Add a new CoMo node
      <form align=middle action=managenode.php method=get>
	<input type=text name=comonode "size=21 value="comonode:44444"
         onFocus=clearText(this);>
	<input type=image src=images/go.jpg >
      </form>
    </td>
  </tr>
</table>
</body>


<?php
    include("include/footer.php.inc");
?>


