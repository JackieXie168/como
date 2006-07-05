<?php 
/*  $Id$  */
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
function zoom_in($start, $end, $node, $basequery, $timebound)
{ 
    $interval = $end - $start; 

    if ($interval < $timebound) 
	return "<img src=images/zoom-in.png align=middle>";

    $zstart = $start + floor($interval/4);
    $zend = $end - floor($interval/4);
    $button = "<a href=\"$basequery&start=$zstart&end=$zend\">";
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
function zoom_out($start, $end, $node, $basequery, $timebound)
{ 
    $interval = $end - $start; 

    $zstart = $start - $interval;
    $zend = $end + $interval;

    //  Make sure we don't go into future
    $now = $node->curtime - ($node->curtime % $timebound); 
    if ($zend > $now)  
	$zend = $now;

    $button = "<a href=\"$basequery&start=$zstart&end=$zend\">";
    $button = $button . "<img src=images/zoom-out.png align=middle></a>";

    return $button; 
} 

/* 
 * -- forward 
 * 
 * return a string with the image for the zoom-out and an anchor
 * to the query with the same interval shifted by half interval forward. 
 */ 
function forward($start, $end, $node, $basequery, $timebound)
{ 
    $now = $node->curtime - ($node->curtime % $timebound); 

    if ($end >= $now)
	return "<img src=images/forward.png align=middle>";

    $shift = floor(($end - $start)/2); 
    $fstart = $start + $shift; 
    $fend = $end + $shift; 

    $shift /= 60; 
    $shift_text = "Forward $shift minutes";
    if ($shift > 60) { 
	$shift /= 60; 
	$shift_text = "Forward $shift hours"; 
    } 
    
    $button = "<a href=\"$basequery&start=$fstart&end=$fend\">";
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
function backward($start, $end, $node, $basequery, $timebound)
{ 
    $past = $node->start - ($node->start % $timebound); 

    if ($start <= $past)
	return "<img src=images/backward.png align=middle>";

    $shift = floor(($end - $start)/2); 
    $fstart = $start - $shift; 
    $fend = $end - $shift; 

    $shift /= 60; 
    $shift_text = "Backward $shift minutes";
    if ($shift > 60) { 
	$shift /= 60; 
	$shift_text = "Backward $shift hours"; 
    } 
    
    $button = "<a href=\"$basequery&start=$fstart&end=$fend\">";
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
function until_now($start, $end, $basequery)
{
    $button = "<a href=\"$basequery&start=$start&end=$end\">";
    $button = $button . "<img src=images/forward-now.png align=middle ";
    $button = $button . "alt=\"forward until present time\"></a>";

    return $button;
}

?>
