<!--  $Id$  -->

<?php
    $includebanner=1;
    include("include/header.php.inc");

    $no_areas = 1; 
    $region[0] = $_GET['area'];

    if (ereg("all", $region[0])) { 
	$no_areas = 7; 
	$region[0] = "europe"; 
	$region[1] = "northamerica"; 
	$region[2] = "south_america"; 
	$region[3] = "asia"; 
	$region[4] = "africa"; 
	$region[5] = "oceania"; 
	$region[6] = "other"; 
    } 
 
    for ($i = 0; $i < $no_areas; $i++) { 
        $filename = $NODEDB."/".$region[$i].".lst"; 

	if (!file_exists($filename)) 
	    continue; 

	$fp = fopen($filename, "r"); 
	/* 
	 * The first line of each file will be used as is
	 * to make the title of the section 
	 */
	$areainfo = fgets($fp); 
	print "<div id=areatitle>$areainfo</div>";

	/* 
	 * the other lines contain the following information:
	 *   . node name
	 *   . installation date 
	 *   . data source
	 *   . link speed
	 *   . status (private, protected, public)
	 */
	print "<table cellpadding=0 cellspacing=0 border=0>";
	while (!feof($fp)) { 
	    $line = fgets($fp); 
            if ($line != ""){
		list($comonode, $name, $loc, $iface, $src) = split(';', $line); 
		print "<tr>";
		print "<td width=200>"; 
		if ($comonode != " ") 
		    print "<a href=dashboard.php?comonode=$comonode>$name</a>"; 
		else 
		    print "$name"; 
		print "</td>"; 
		print "<td width=250>$loc</td>"; 
		print "<td width=150>$iface</td>"; 
		print "<td width=200>$src</td>"; 
		print "</tr>"; 
	    } 
        }
	print "</table>";
    
	fclose($fp); 
    }

    print "<br>";
    include("include/footer.php.inc"); 
?>

