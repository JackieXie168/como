<?php
	/*  $Id$  */
	$ABSROOT = preg_replace('/\/groups.*/', '', $_SERVER['SCRIPT_FILENAME']);
    require_once("$ABSROOT/comolive.conf");
    $G = init_global();

	$url = "";
	if (isset($_SERVER['QUERY_STRING'])) {
		$url = $_SERVER['QUERY_STRING'];
	}
?>
<html>
<head>
</head>
<link rel="stylesheet" type="text/css" href="<?php echo $G['WEBROOT']?>css/mainstage.css">
<script language="JavaScript" src="<?php echo $G['WEBROOT']?>/js/loading.js"></script>
</head>
    <body onload="showLoading('mainstage.php?<?php echo $url ?>')">
    <div id=loading>
	<img src="<?php echo $G['WEBROOT']?>/images/loading.gif">
    </div>

    <div id=content> <div>
    </body>
</html>
