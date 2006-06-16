<!-- $Id -->

<?php 

/* 
 * -- zoom_in 
 * 
 * return a string with the image for the zoom-in and an anchor
 * to the query with an interval that is half of the original 
 * interval and centered in the middle of the original interval. 
 * If the interval is too small, return just the HTML code to 
 * show the image. 
 * 
 */ 
function zoom_in($stime, $etime, $node, $basequery, $timebound)
{ 
    $interval = $etime - $stime; 

    if ($interval < $timebound) 
	return "<img src=images/zoom-in.png align=middle>";

    $zstime = $stime + floor($interval/4);
    $zetime = $etime - floor($interval/4);
    $button = "<a href=\"$basequery&stime=$zstime&etime=$zetime\">";
    $button = $button . "<img src=images/zoom-in.png align=middle></a>";

    return $button; 
} 

/* 
 * -- zoom_out 
 * 
 * return a string with the image for the zoom-out and an anchor
 * to the query with an interval that is three times the original 
 * interval and centered in the middle of the original interval. 
 */ 
function zoom_out($stime, $etime, $node, $basequery, $timebound)
{ 
    $interval = $etime - $stime; 

    $zstime = $stime - $interval;
    $zetime = $etime + $interval;

    //  Make sure we don't go into future
    $now = $node->curtime - ($node->curtime % $timebound); 
    if ($zetime > $now)  
	$zetime = $now;

    $button = "<a href=\"$basequery&stime=$zstime&etime=$zetime\">";
    $button = $button . "<img src=images/zoom-out.png align=middle></a>";

    return $button; 
} 

/* 
 * -- forward 
 * 
 * return a string with the image for the zoom-out and an anchor
 * to the query with the same interval shifted by half interval forward. 
 */ 
function forward($stime, $etime, $node, $basequery, $timebound)
{ 
    $now = $node->curtime - ($node->curtime % $timebound); 

    if ($etime >= $now)
	return "<img src=images/forward.png align=middle>";

    $shift = floor(($etime - $stime)/2); 
    $fstime = $stime + $shift; 
    $fetime = $etime + $shift; 

    $shift /= 60; 
    $shift_text = "Forward $shift minutes";
    if ($shift > 60) { 
	$shift /= 60; 
	$shift_text = "Forward $shift hours"; 
    } 
    
    $button = "<a href=\"$basequery&stime=$fstime&etime=$fetime\">";
    $button = $button . "<img src=images/forward.png align=middle ";
    $button = $button . "alt=\"$shift_text\"></a>";

    return $button; 
} 


/* 
 * -- backward 
 * 
 * return a string with the image for the zoom-out and an anchor
 * to the query with the same interval shifted by half interval
 * backward. 
 */ 
function backward($stime, $etime, $node, $basequery, $timebound)
{ 
    $past = $node->start - ($node->start % $timebound); 

    if ($stime <= $past)
	return "<img src=images/backward.png align=middle>";

    $shift = floor(($etime - $stime)/2); 
    $fstime = $stime - $shift; 
    $fetime = $etime - $shift; 

    $shift /= 60; 
    $shift_text = "Backward $shift minutes";
    if ($shift > 60) { 
	$shift /= 60; 
	$shift_text = "Backward $shift hours"; 
    } 
    
    $button = "<a href=\"$basequery&stime=$fstime&etime=$fetime\">";
    $button = $button . "<img src=images/backward.png align=middle "; 
    $button = $button . "alt=\"$shift_text\"></a>";

    return $button; 
} 


/* 
 * -- detail_button 
 * 
 * returns a string to a detailed query with the "detail" button 
 * over the same interval. 
 *
 */
function detail_button($basequery)
{ 
    $button = "<a target=new href=\"$basequery\">";
    $button = $button . "<img src=images/zoom-ascii.png align=middle ";
    $button = $button . "alt=\"Details\"></a>";
    return $button; 
} 


/*
 * -- until_now
 *
 * go forward until current time 
 * 
 */
function until_now($stime, $etime, $basequery)
{
    $button = "<a href=\"$basequery&stime=$stime&etime=$etime\">";
    $button = $button . "<img src=images/forward-now.png align=middle ";
    $button = $button . "alt=\"forward until present time\"></a>";

    return $button;
}

?>
