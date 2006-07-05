<?
/*  $Id:$  */
$url = "";
if (isset($_SERVER['QUERY_STRING']))
    $url = $_SERVER['QUERY_STRING'];

?>
<html>
<head>
<style>
    #loading {
        font-size : 20px;
        text-align : center;
        display : none;
    }
    #content {
    }
</style>
</head>
<link rel="stylesheet" type="text/css" href="css/mainstage.css">
<script language="JavaScript" src="js/loading.js"></script>
</head>
    <body onload="showLoading('mainstage.php?<?=$url?>')">
    <div id=loading>
	<img src=images/loading.gif>
    </div>

    <div id=content> <div>
    </body>
</html>
