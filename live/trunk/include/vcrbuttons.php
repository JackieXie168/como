<div id=controls>

<?php 
    $timeperiod = $etime - $stime; 
    $now = gettimeofday(); 
    $now["sec"] -= $delay; 

    /* 
     * Zoom in  -- halve the timeperiod 
     */
    if ($timeperiod > $GRANULARITY) {
	$zstime = $stime + floor($timeperiod/4);
	$zetime = $etime - floor($timeperiod/4);
	print "<a href=\"system.php?node=$host&module=$mdl";
	if (!is_null($filter)) 
	    print "&filter=$filter";
	else 
	    print "&filter=all"; 
	print "&stime=$zstime&etime=$zetime\">\n";
	print "<img src=images/zoom-in.png></a>\n";
    } else {
	print "<img src=images/zoom-in.png>\n";
    }

    /* 
     * Zoom out  -- triple the timeperiod
     */
    $zstime = floor($stime - $timeperiod);
    $zetime = floor($etime + $timeperiod);

    //  Make sure we don't go into future
    if ($zetime > $now["sec"])  
	$zetime = $now["sec"];

    print "<a href=\"system.php?node=$host&module=$mdl";
    if (!is_null($filter)) 
	print "&filter=$filter";
    else 
        print "&filter=all"; 
    print "&stime=$zstime&etime=$zetime\">\n";
    print "<img src=images/zoom-out.png></a>\n";

    /* 
     * ASCII  -- open a window with ascii results, same timeperiod
     */
    print "<a target=new href=\"textquery.php?node=$host/?module=$mdl"; 
    if (!is_null($filter)) 
	print "&filter=$filter";
    else 
        print "&filter=all"; 
    print "&start=$stime&end=$etime&format=pretty\">";
    print "<img src=images/zoom-ascii.png alt=\"ASCII Output\"></a>";

    /* 
     * Backwards  -- move backwards by half a timeperiod
     */
    $range_min = floor(($timeperiod/60)/2);
    $bstime = $stime - floor($timeperiod/2);
    $betime = $etime - floor($timeperiod/2);
    print "<a href=\"system.php?node=$host&module=$mdl";
    if (!is_null($filter)) 
	print "&filter=$filter";
    else 
        print "&filter=all"; 
    print "&stime=$bstime&etime=$betime\">\n";
    print "<img src=images/backward.png alt=\"Back $range_min minutes\"></a>\n";

    /* 
     * Forewards  -- move forward by half a timeperiod
     */
    if ($etime < $now["sec"]){
	$fstime = $stime + floor($timeperiod/2);
	$fetime = $etime + floor($timeperiod/2);
	print "<a href=\"system.php?node=$host&module=$mdl";
	if (!is_null($filter)) 
	    print "&filter=$filter";
	else 
	    print "&filter=all"; 
	print "&stime=$fstime&etime=$fetime\">\n";
        print "<img src=images/forward.png alt=\"Forward $range_min minutes\"></a>\n";
    }else{
    ?>
        <img src=images/forward.png>
    <?
    }
?>
</div>
