<!--  $Id$  -->
<?php 

    /* we need to create the string of parameters to be sent to 
     * the flash movie. we need to send the URL where the image is, 
     * plus some additional information about the module and the timestamps.
     */

    /* where to find the image */
    $docroot = dirname($_SERVER['SCRIPT_NAME']);
    $info = "image=http://" . $_SERVER['HTTP_HOST']; 
    $info .= $docroot . "/" . $filename . ".jpg"; 

    /* where to find the cursor */
    $info .= "&cursor=$docroot/flash/global_cursor.swf";

    /* the query that the flash client needs to send back */
    $info .= "&link=dashboard.php&target=_TOP";
    $info .= "&comonode=$comonode&module=$module";
    $info .= "&start=$start&end=$end&format=gnuplot&";
    $info .= "$http_query_string";
#    $info = urlencode($info);
?>

<object classid="clsid:d27cdb6e-ae6d-11cf-96b8-444553540000" 
        codebase="http://macromedia.com/cabs/flash/swflash.cab#version=7,0,0,0" 
        width="600" height="450" id="zooming" align="middle">
    <param name="allowScriptAccess" value="sameDomain">
    <param name="movie" value="<?php echo $docroot?>/flash/zooming.swf?<?php echo($info);?>">
    <param name="loop" value="false">
    <param name="menu" value="false">
    <param name="quality" value="medium">
    <param name="salign" value="r">
    <param name="wmode" value="opaque">
    <param name="bgcolor" value="#ffffff">
    <embed src="<?php echo $docroot?>/flash/zooming.swf?<?php echo($info);?>"
	   loop="false" menu="false" quality="medium"  salign="r"  
           wmode="opaque" bgcolor="#ffffff" width="600" height="450" 
           name="zoom" align="middle" allowScriptAccess="sameDomain" 
           type="application/x-shockwave-flash" 
           pluginspage="http://www.macromedia.com/go/getflashplayer">
</object>
