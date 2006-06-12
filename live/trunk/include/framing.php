<!--  $Id: header.php.inc 600 2006-06-05 11:59:59Z iannak1 $  -->
<?php

function print_header($banner, $comonode) { 
    $style = "css/live.css";
    $pagetitle = "CoMolive! - Intel Research Cambridge";

    print "<html><head>\n"; 
    print "<title>$pagetitle</title>\n";
    print "<link rel=stylesheet type=text/css name=como href=$style>\n";
    print "<link rel=\"shortcut icon\" href=\"images/favicon.ico\">\n";
    print "<meta http-equiv=\"Content-Type\" content=\"text/html; "; 
    print "charset=iso-8859-1\">\n";
    print "<meta name=description content=CoMolive!>\n";
    print "</head>\n";

    /* comolive.conf is the global configuration file  */
    if (!file_exists("comolive.conf")) {
        print "Please create a comolive.conf file";
        return FALSE;
    }
        
    if ($banner) {
        $webroot = dirname($_SERVER['SCRIPT_NAME']);
	print "<div id=header><a href=$webroot>";
	print "<img src=images/comolive-smooth.png></a></div>\n";
        include ("mainmenu.php");
    } 

    return TRUE; 
}

function print_footer() { 
    $cur_date = getdate(time());

    print "<div id=footer>\n";
    print "Copyright &#169; 2004-{$cur_date['year']} Intel Corporation -- \n";
    print "<a href=\"http://www.intel.com/sites/corporate/tradmarx.htm\">\n";
    print "Legal Information</a> and \n";
    print "<a href=\"http://www.intel.com/sites/corporate/privacy.htm\">\n";
    print "Privacy Policy</a>\n";
    print "</div></body></html>\n";
}

?>
