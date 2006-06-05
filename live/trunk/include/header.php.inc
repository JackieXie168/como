<!--  $Id$  -->
<?php
    /* 
     *  Set these vars in pages to alter how header works
     *  $includebanner=1      Include the default como banner
     *  $stylesheet="value"   set the style sheet to be "value"
     */ 

    if (!(isset($stylesheet)))
	$stylesheet = "css/live.css";
    if (!(isset($includebanner)))
	$includebanner=0;
    if (!(isset($pagetitle)))
	$pagetitle = "CoMolive! - Intel Research Cambridge";
    else
	$pagetitle = "$pagetitle - CoMolive! - Intel Research Cambridge";
?>

<html>
<head>
  <title><?=$pagetitle?></title>
  <link rel="stylesheet" type="text/css" name="como" href="<?=$stylesheet?>">
  <link rel="shortcut icon" href="images/favicon.ico">
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
  <meta name="description" content="CoMolive!">
</head>

<?php
    /* comolive.conf is the global configuration file  */
    if (file_exists("comolive.conf")) {
	require_once ("comolive.conf");
        $G = init_global ();
    } else {
        print "Please create a comolive.conf file";
        exit;
    }
        
    if ($includebanner) {
        $checkindex = basename ($_SERVER['SCRIPT_NAME']);
	print "<div id=header><a href={$G['WEBROOT']}>";
	print "<img src=images/comolive-smooth.png></a></div>\n";
        include ("include/mainmenu.php");
    } 
?>
