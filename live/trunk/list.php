<!-- $Id$ --> 

<html>

<?php include("comolive.conf"); ?>
<?php $nodename = NULL; include("include/header.php"); ?>
<?php $level = "top"; include("include/menulist.php"); ?>

<div id=content> 
<?php 
    $no_areas = 1; 
    $area[0] = $_GET['area'];

    if (ereg("all", $area[0])) { 
	$no_areas = 7; 
	$area[0] = "europe"; 
	$area[1] = "north_america"; 
	$area[2] = "south_america"; 
	$area[3] = "asia"; 
	$area[4] = "africa"; 
	$area[5] = "oceania"; 
	$area[6] = "others"; 
    } 
 
    for ($i = 0; $i < $no_areas; $i++) { 
        $filename = $_SERVER['DOCUMENT_ROOT'].$NODEDB."/".$area[$i].".list";   

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


