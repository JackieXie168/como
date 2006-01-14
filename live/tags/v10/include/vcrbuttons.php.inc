<div id=controls>

<?php 
    require_once("comolive.conf");
    $interval = $etime - $stime; 
    #$now = gettimeofday(); 
    $now = $node->curtime;
    /* 
     * Zoom in  -- halve the interval 
     */
    if ($interval > $TIMEBOUND) {
	$zstime = $stime + floor($interval/4);
	$zetime = $etime - floor($interval/4);
	print "<a href=\"dashboard.php?comonode=$comonode";
        print "&module=$module";
	if ($module == $special) {
	    $duration = $zetime - $zstime; 
	    print "&source=tuple&interval=$interval";
	}
	if (!is_null($filter)) 
	    print "&filter=$filter";
	else 
	    print "&filter=all"; 
	print "&stime=$zstime&etime=$zetime\">\n";
	print "<img src=images/zoom-in.png alt\"testing\"></a>\n";
    } else {
	print "<img src=images/zoom-in.png>\n";
    }

    /* 
     * Zoom out  -- triple the interval
     */
    $zstime = floor($stime - $interval);
    $zetime = floor($etime + $interval);

    //  Make sure we don't go into future
    if ($zetime > $now)  
	$zetime = $now;

    print "<a href=\"dashboard.php?comonode=$comonode&module=$module";
    if ($module == $special) {
	$duration = $zetime - $zstime; 
	print "&source=tuple&interval=$interval";
    }
    if (!is_null($filter)) 
	print "&filter=$filter";
    else 
        print "&filter=all"; 
    print "&stime=$zstime&etime=$zetime\">\n";
    print "<img src=images/zoom-out.png></a>\n";

    /* 
     * ASCII  -- open a window with flow records same interval 
     */
    print "<a target=new href=\"generic_query.php?"; 
    print "comonode=$comonode&module=tuple&filter=ip&"; 
    print "source=tuple&interval=$interval&"; 
    print "start=$stime&end=$etime&format=html\">";
    print "<img src=images/zoom-ascii.png alt=\"ASCII Output\"></a>";

    /* 
     * Backwards  -- move backwards by half a interval
     */
    $range_min = floor(($interval/60)/2);
    $bstime = $stime - floor($interval/2);
    $betime = $etime - floor($interval/2);
    print "<a href=\"dashboard.php?comonode=$comonode&module=$module";
    if ($module == $special) {
	$duration = $zetime - $zstime; 
	print "&source=tuple&interval=$interval";
    }
    if (!is_null($filter)) 
	print "&filter=$filter";
    else 
        print "&filter=all"; 
    print "&stime=$bstime&etime=$betime\">\n";
    print "<img src=images/backward.png alt=\"Back $range_min minutes\"></a>\n";

    /* 
     * Forewards  -- move forward by half a interval
     */
    if ($etime < $now){
	$fstime = $stime + floor($interval/2);
	$fetime = $etime + floor($interval/2);
	print "<a href=\"dashboard.php?comonode=$comonode&module=$module";
	if ($module == $special) {
	    $duration = $zetime - $zstime; 
	    print "&source=tuple&interval=$interval";
	}
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
