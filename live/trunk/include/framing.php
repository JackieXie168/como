<?php
/*  $Id$  */
/* 
 * -- do_header 
 * 
 * returns header string with banner image, menu items and 
 * javascript code for the submenus. 
 *
 */ 
function do_header($comonode, $G) 
{ 
    $webroot = $G['WEBROOT'];
    $customize = $G['ALLOWCUSTOMIZE'];

    $header = "<script language=\"JavaScript\" src=js/mainmenu.js></script>\n" .
	      "<div id=header><a href=\"$webroot\">" . 
	      "<img src=images/comolive-smooth.png></a></div>\n";

    /* 
     * add the main menu. (note that the &nbsp; around the menu items
     * are needed for aesthetical reasons). 
     */ 
    $header = $header . "<div id=menubar><ul>\n"; 
    $param = "webroot=$webroot&comonode=$comonode";
    if ($customize) 
	$param = $param . "&customize=1";

    if (!is_null($comonode)) {
	// $param = $param . "&comonode=$comonode";
        $header = $header .  "<li>\n<a href=# " . 
		  "onclick=\"startMenuRequest('system&$param');\">" . 
		  "&nbsp;&nbsp;&nbsp;System&nbsp;&nbsp;&nbsp;</a></li>\n";
    } 

    $header = $header . "<li>\n<a href=# " .
	      "onclick=\"startMenuRequest('view&$param');\">" . 
	      "&nbsp;&nbsp;&nbsp;View&nbsp;&nbsp;&nbsp;</a></li>\n";

    $header = $header . "<li>\n<a href=# " .
	      "onclick=\"startMenuRequest('help&$param');\">" . 
	      "&nbsp;&nbsp;&nbsp;Help&nbsp;&nbsp;&nbsp;</a></li>\n";

    $header = $header . "</ul>\n<div id=\"results\"></div></div>\n";

    return $header; 
}


/* 
 * XXX legacy function. it should go once all code is using 
 *     HTML templates. 
 */ 
function print_header($banner, $comonode) { 
    $style = "css/live.css";
    $pagetitle = "CoMolive! - Intel Research Cambridge";

    print "<html><head>\n"; 
    print "<title>$pagetitle</title>\n";
    print "<link rel=stylesheet type=text/css name=como href=$style>\n";
    print "<link rel=\"shortcut icon\" href=\"images/favicon.ico\">\n";
    print "<meta http-equiv=\"Content-Type\" content=\"text/html; "; 
    print "charset=iso-8859-1\">\n";
    print "<meta name=description content=\"CoMolive!\">\n";
    print "</head>\n";

        
    if ($banner) 
	print do_header($comonode, true); 

    return TRUE; 
}


/* 
 * -- do_footer
 * 
 * returns string with footer that include the copyright information 
 *
 */
function do_footer() 
{
    $now = getdate(time());

    $footer = "<div id=footer>\n" . 
	"Copyright &#169; 2005-{$now['year']} Intel Corporation --\n" .
	"<a href=\"http://www.intel.com/sites/corporate/tradmarx.htm\">" . 
	"Legal Information</a> and \n" .
	"<a href=\"http://www.intel.com/sites/corporate/privacy.htm\">\n" .
	"Privacy Policy</a></div>\n" . 
        "</body></html>\n";

    return $footer; 
}


/* 
 * XXX legacy function. it should go once all code is using 
 *     HTML templates. 
 */ 

function print_footer() { 
    print do_footer(); 
    print "</body></html>\n";
}

?>


