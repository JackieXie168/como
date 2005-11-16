<!-- $Id$ --> 

<html>

<?php include("comolive.conf"); ?>
<?php $nodename = NULL; include("include/header.php"); ?>
<?php $level = "top"; include("include/menulist.php"); ?>

<div id=content> 
<?php 
    $no_areas = 1; 
    $region[0] = $_GET['area'];

    if (ereg("all", $region[0])) { 
	$no_areas = 7; 
	$region[0] = "europe"; 
	$region[1] = "north_america"; 
	$region[2] = "south_america"; 
	$region[3] = "asia"; 
	$region[4] = "africa"; 
	$region[5] = "oceania"; 
	$region[6] = "others"; 
    } 
 
    for ($i = 0; $i < $no_areas; $i++) { 
        $filename = $_SERVER['DOCUMENT_ROOT'].$NODEDB."/".$region[$i].".list"; 

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
	print "<table cellpadding=2 cellspacing=2>";
	while (!feof($fp)) { 
	    $line = fgets($fp); 
	    list($host, $name, $place, $source, $speed) = split(';', $line, 6); 

	    print "<tr>";
	    print "<td width=200>"; 
 	    if ($host != "") 
		print "<a href=system.php?node=$host>$name</a>"; 
	    else 
 	        print "$name"; 
	    print "</td>"; 
 	    print "<td width=250>$place</td>"; 
 	    print "<td width=150>$source</td>"; 
 	    print "<td width=200>$speed</td>"; 
	    print "</tr>"; 
	} 
	print "</table>";
    
	fclose($fp); 
    }

    print "<br>";
?>
    

</div>

<?php include("include/footer.php"); ?>
</html>


