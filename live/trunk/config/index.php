<!--  $Id$  -->
<?php
$REVISION = substr('\$Revision$', 11, -2);

/*  This file creates the main configuration file for CoMoLive!  */
/*  Include the framing information to create headers and footers  */     
include("../include/framing.php");
include("../include/helper-messages.php");

$header = simple_header("../");
$footer = simple_footer();

/*  This is our way of initially finding the location of the webserver
 *  root directory.  Once this page loads, it gives you the option 
 *  to change it to another directory.
 */
$webroot = ereg_replace("/config.*", "",  $_SERVER['SCRIPT_NAME']);
$absroot = ereg_replace("/config.*", "",  $_SERVER['SCRIPT_FILENAME']);

/*  Check if the comolive.conf file already exists  */
if (file_exists("../comolive.conf")) {
    $m = "CoMoLive! is already configured.  If you are having a <br>" . 
         "problem, you should post your issue to the mailing " . 
         "list.<br><br>" .
         "Click <a href=$webroot/>here</a>";
    generic_message($m);
}

/*  Make sure the config directory is writable by the webserver  */
    $dir = "$absroot/config";
    $val = check_writable($dir);
    if (!(check_writable($dir))) {
        generic_message(ERROR_DIRNOTWRITABLE($dir));
    }


/*  This var is passed upon itself to let it know what to do  */
$action = "setup";
if (isset($_GET['action']))
    $action = $_GET['action'];

/*  Brief description of the options in the file  */
$TIMEPERIOD_DESC = "The default amount of time that CoMo should\n" .
                   "query initially (in seconds)";

$TIMEBOUND_DESC = "Define the granularity for all graphs (in seconds),\n" . 
                  "i.e., all timestamps will be aligned to this\n" . 
                  "granularity";

$RESOLUTION_DESC = "Define the resolutions of graphs, i.e. the number \n" .
                   "of points to be present in a graph. This is just \n" .
                   "an indication to the module of the desired \n" . 
                   "resolution.  The actual implementation is \n" . 
                   "module dependant.";  


$RESULTS_DESC = "Where the results will reside for future\n" . 
                "accesses. Path is relative to apache document\n" . 
                "root. Apache needs to have write access to it.";


$NODEDB_DESC = "Directory with the node lists. The path is relative to\n" . 
               "document root and needs to be readable from apache.\n" . 
               "Look into db/README for details.";

$GNUPLOT_DESC = "Path to gnuplot";
$CONVERT_DESC = "Path to convert";

$WEBROOT_DESC = "Path relative to root of webserver";
$ABSROOT_DESC = "Path relative to root of filesystem";
$PASSWORD_DESC = "Password for admin directory";
$DOT_DESC = "Path to dot";
$PYTHON_DESC = "Path to python";

/*  Enter setup mode  */
if ($action == "setup") {
    print "$header";
    include ("config.html");
    print "$footer";
    exit;
} 

/*  Enter install mode  */
$i=0;
$G = array();
if ($action == "install") {
    /*  Create an array with the value and desciption  */
    $G['REV']['val'] = $REVISION;
    if (isset($_POST["TIMEPERIOD"])) {
        $G['TIMEPERIOD']['val'] = $_POST["TIMEPERIOD"];
        $G['TIMEPERIOD']['desc'] = $TIMEPERIOD_DESC;
    }
    if (isset($_POST["TIMEBOUND"])) {
        $G['TIMEBOUND']['val'] = $_POST["TIMEBOUND"];
        $G['TIMEBOUND']['desc'] = $TIMEBOUND_DESC;
    }
    if (isset($_POST["RESOLUTION"])) {
        $G['RESOLUTION']['val'] = $_POST["RESOLUTION"];
        $G['RESOLUTION']['desc'] = $RESOLUTION_DESC;
    }
    if (isset($_POST["RESULTS"])) {
        $G['RESULTS']['val'] = $_POST["RESULTS"];
        $G['RESULTS']['desc'] = $RESULTS_DESC;
    }
    if (isset($_POST["NODEDB"])) {
        $G['NODEDB']['val'] = $_POST["NODEDB"];
        $G['NODEDB']['desc'] = $NODEDB_DESC;
    }
    if (isset($_POST["GNUPLOT"])) {
        $G['GNUPLOT']['val'] = $_POST["GNUPLOT"];
        $G['GNUPLOT']['desc'] = $GNUPLOT_DESC;
    }
    if (isset($_POST["CONVERT"])) {
        $G['CONVERT']['val'] = $_POST["CONVERT"];
        $G['CONVERT']['desc'] = $CONVERT_DESC;
    }
    if (isset($_POST["WEBROOT"])) {
        $G['WEBROOT']['val'] = $_POST["WEBROOT"];
        $G['WEBROOT']['desc'] = $WEBROOT_DESC;
    }
    if (isset($_POST["ABSROOT"])) {
        $G['ABSROOT']['val'] = $_POST["ABSROOT"];
        $G['ABSROOT']['desc'] = $ABSROOT_DESC;
    }
    if (isset($_POST["PASSWORD"])) {
        $G['PASSWORD']['val'] = $_POST["PASSWORD"];
        $G['PASSWORD']['desc'] = $PASSWORD_DESC;
    }
    /*  Make sure the results and db directory exists  */
    $dir = "$absroot/{$G['NODEDB']['val']}";
    $val = check_writable($dir);
    if (!(check_writable($dir))) {
        generic_message(ERROR_DIRNOTWRITABLE($dir));
    }
    $dir = "$absroot/{$G['RESULTS']['val']}";
    if (!(check_writable($dir))) {
        generic_message(ERROR_DIRNOTWRITABLE($dir));
    }
    $dir = "$absroot/admin";
    if (!(check_writable($dir))) {
        generic_message(ERROR_DIRNOTWRITABLE($dir));
    }

    /*  create the public and admin site directories  */
    $dir = "$absroot/public";
    if (!(file_exists($dir))) {
        create_site($G, "public");
    }
    create_site($G, "admin");
    /*  Write configuration file to disk  */
    write_config($G, "comolive.conf");
    $m = "Configuration complete.  Copy the comolive.conf file " .
         "to the web root.<br><pre>" . 
         "mv $absroot/config/comolive.conf $webroot/<br></pre>" .
         "You can make changes to the config file by " . 
         "editing comolive.conf<br>" . 
         "Click <a href=$webroot/>here</a> when you have moved the file";
    generic_message($m);
}

/*  Function to write the config file.  Changes to comolive.conf should
 *  be made here 
 */
function write_config($G, $outfile) {
    $c = "<?php\n" . 
    "/*\n" . 
    " * CoMolive! configuration file\n" .
    " * This file is automatically generated.\n" .
    " */\n\n" .
    "function init_global() { \n\n" .
    "    /* \n" . 
    "     * CoMoLive! Version \n" .
    "     */ \n\n" .
    "    \$GLOBAL['VERSION'] = 1.0; \n" .
    "    \$GLOBAL['REV'] = " . $G['REV']['val'] . ";\n\n";
    $tmp = comment($G['TIMEPERIOD']['desc']);
    $c .= $tmp;
    $c .= "    \$GLOBAL['TIMEPERIOD'] = " . $G['TIMEPERIOD']['val'] . ";\n\n";
    $tmp = comment($G['TIMEBOUND']['desc']);
    $c .= $tmp;
    $c .= "    \$GLOBAL['TIMEBOUND'] = " . $G['TIMEBOUND']['val'] . ";\n\n"; 
    $tmp = comment($G['RESOLUTION']['desc']);
    $c .= $tmp;
    $c .= "    \$GLOBAL['RESOLUTION'] = 200;\n" .
    $tmp = comment($G['RESULTS']['desc']);
    $c .= $tmp;
    $c .= "    \$GLOBAL['RESULTS'] = \"" . $G['RESULTS']['val'] . "\";\n\n";
    $tmp = comment($G['NODEDB']['desc']);
    $c .= $tmp;
    $c .= "    \$GLOBAL['NODEDB'] = \"" . $G['NODEDB']['val'] . "\";\n\n";
    $tmp = comment($G['GNUPLOT']['desc']);
    $c .= $tmp;
    $c .= "    \$GLOBAL['GNUPLOT'] = \"" . $G['GNUPLOT']['val'] . "\";\n\n";
    $tmp = comment($G['CONVERT']['desc']);
    $c .= $tmp;
    $c .= "    \$GLOBAL['CONVERT'] = \"" . $G['CONVERT']['val'] . 
    " -density 200x200 -resize 600x450\";\n\n" .
    $tmp = comment($G['WEBROOT']['desc']);
    $c .= $tmp;
    $c .= "    \$GLOBAL['WEBROOT'] = \"" . $G['WEBROOT']['val'] . "\";\n\n" .
    $tmp = comment($G['ABSROOT']['desc']);
    $c .= $tmp;
    $c .= "    \$GLOBAL['ABSROOT'] = \"" . $G['ABSROOT']['val'] . "\";\n\n" .
    "     /*\n" .
    "     *  Error report values are defined on php.net\n" .
    "     *  Set to 'E_ALL' for debugging or '0' for none\n" .
    "     */\n" .
    "    \$errorreport = 0;  /*  No error reporting  */\n" .
    "    #\$errorreport = E_ALL;  /*  Display all errors  */\n\n" .
    "    \$GLOBAL['ERROR_REPORTING'] = \$errorreport;\n" .
    "    error_reporting(\"\$errorreport\");\n\n" .
    "    /* select if using Flash or not */\n" .
    "    \$browser = \$_SERVER['HTTP_USER_AGENT']; \n\n" .
    "    if (stristr(\$browser, \"msie\")) {  \n" .
    "	     \$GLOBAL['USEFLASH'] = 1; \n" .
    "    } else { \n" .
    "	     \$GLOBAL['USEFLASH'] = 0; \n" .
    "    }\n\n" .
    "    /* Customize your logo here */\n" .
    "    \$GLOBAL['MYLOGO'] = \"./images/intel.gif\";\n\n" .
    "    /* Use file caching \n" .
    "     * Some pages will have the opportunity to write data to files.\n" .
    "     * Use this option to utilize this feature or turn it \n" .
    "     * off to force a regeneration of the data. \n" .
    "     * It usually should be on.\n" .
    "     */\n" .
    "    \$GLOBAL['USECACHE'] = 1;\n\n" .
    "    /* Allow customization of CoMoLive! */\n" .
    "    \$GLOBAL['ALLOWCUSTOMIZE'] = 1;\n\n" .
    "    /*  Use BlincView  */\n" .
    "    \$GLOBAL['USEBLINCVIEW'] = 0;\n" .
    "    \$GLOBAL['BLINCVIEWCMD'] = \"./contrib/blinc/blincview_dst.py\";\n\n" .
    "    /*  If you use BlincView, you will need to \n" .
    "     *  install DOT (http://graphviz.org) and python \n\n" .
    "    \$GLOBAL['DOT'] = \"/usr/local/bin/dot\";\n" .
    "    \$GLOBAL['PYTHON'] = \"/usr/bin/python\"; \n\n" .
    "    /*  Return the Variable  */\n" .
    "    return(\$GLOBAL);\n" .
    "}\n" .
    "?>";
    file_put_contents($outfile, $c);
}

/**
 *  Function to convert the DESC vars to print nicely in the config 
 *  file  
 */
function comment ($val) 
{
    $rep = "\n     * ";
    $newval = "    /*\n     * ";
    $test = ereg_replace("\n", $rep , $val);
    $newval = $newval . $test . "\n     */\n\n";
    return $newval;
}
/**
 *  Function to create the site.  Create all links to necessary files  
 */
function create_site ($G, $sitename) 
{
    $dname = $G['ABSROOT']['val'] . "/" . $sitename;
    $srcname = $G['ABSROOT']['val'] . "/php";
    if ($sitename != "admin") {
        /*  Create the site directory  */
        mkdir ($dname, 0755);
        /*  Create the sym links  */
        $symname[0] = "dashboard.php";
        $symname[1] = "generic_query.php";
        $symname[2] = "index.php";
        $symname[3] = "loadcontent.php";
        $symname[4] = "mainstage.php";
        $symname[5] = "sysinfo.php";
        for ($i = 0; $i < count($symname); $i++) {
            $orig = $srcname . "/" . $symname[$i];
            $dest = $dname . "/" . $symname[$i];
            symlink($orig, $dest);
        }
        /*  Create the results and db directory  */
        mkdir("$dname/{$G['RESULTS']['val']}", 0755);
        mkdir("$dname/{$G['NODEDB']['val']}", 0755);
    } else {
        /*  Create the links to db and results  */
print "creat links";
        $orig = $G['ABSROOT']['val'] . "/db";
        $dest = $G['ABSROOT']['val'] . "/admin/db";
        symlink($orig, $dest);
        $orig = $G['ABSROOT']['val'] . "/results";
        $dest = $G['ABSROOT']['val'] . "/admin/results";
        symlink($orig, $dest);
        /*  Write out .htpasswd and .htaccess files  */
        $htpwd = $G['ABSROOT']['val'] . "/admin";
        $htaccess = "AuthName \"CoMoLive! Admin\"\n" . 
                    "AuthType Basic\n" . 
                    "AuthUserFile $htpwd/.htpasswd\n" . 
                    "Require valid-user\n";
        system ("htpasswd -b -c $htpwd/.htpasswd admin {$G['PASSWORD']['val']}");
        file_put_contents("$htpwd/.htaccess", $htaccess);
    }
}

function check_writable ($dir)
{
    /*  This will check to make sure all directories are there and
     *  writeable.
     */
    if (!(file_exists($dir)) || (!(is_writable($dir)))) {
        return 0;
    } else {
        return 1;
    }

}
?>
