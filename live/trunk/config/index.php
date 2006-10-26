<!--  $Id$  -->
<?php
$REVISION = substr('\$Revision$', 11, -2);

require("../include/compat.php");

/*  This file creates the main configuration file for CoMoLive!  */
/*  Include the framing information to create headers and footers  */     
include("../include/framing.php");
include("../include/helper-messages.php");
include("../include/helper-filesystem.php");
include("../class/groupmanager.class.php");

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

/*  Array with all the options */
$opts = array('TIMEPERIOD', 'TIMEBOUND', 'RESOLUTION', 'RESULTS', 'NODEDB',
    'GNUPLOT', 'CONVERT', 'WEBROOT', 'ABSROOT', 'PASSWORD', 'DOT', 'PYTHON');

/*  Brief description of the options in the file  */
$desc['TIMEPERIOD'] = "The default amount of time that CoMo should\n" .
                   "query initially (in seconds)";

$desc['TIMEBOUND'] = "Define the granularity for all graphs (in seconds),\n" . 
                  "i.e., all timestamps will be aligned to this\n" . 
                  "granularity";

$desc['RESOLUTION'] = "Define the resolutions of graphs, i.e. the number \n" .
                   "of points to be present in a graph. This is just \n" .
                   "an indication to the module of the desired \n" . 
                   "resolution.  The actual implementation is \n" . 
                   "module dependant.";  


$desc['RESULTS'] = "Where the results will reside for future\n" . 
                "accesses. Path is relative to apache document\n" . 
                "root. Apache needs to have write access to it.";


$desc['NODEDB'] = "Directory with the node lists. The path is relative to\n" . 
               "document root and needs to be readable from apache.\n" . 
               "Look into db/README for details.";

$desc['GNUPLOT'] = "Path to gnuplot";
$desc['CONVERT'] = "Path to convert";

$desc['WEBROOT'] = "Path relative to root of webserver";
$desc['ABSROOT'] = "Path relative to root of filesystem";
$desc['PASSWORD'] = "Password for admin directory";
$desc['DOT'] = "Path to dot";
$desc['PYTHON'] = "Path to python";



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
    /*  Create an array with the value and description  */
    $G['REV'] = $REVISION;
    foreach ($opts as $opt) {
        if (isset($_POST[$opt])) {
            $G[$opt] = $_POST[$opt];
        }
    }

    /*  Make sure the results and db directory exists  */
    $dir = "$absroot/{$G['NODEDB']}";
    $val = check_writable($dir);
    if (!(check_writable($dir))) {
        generic_message(ERROR_DIRNOTWRITABLE($dir));
    }
    $dir = "$absroot/{$G['RESULTS']}";
    if (!(check_writable($dir))) {
        generic_message(ERROR_DIRNOTWRITABLE($dir));
    }
    $dir = "$absroot/admin";
    if (!(check_writable($dir))) {
        generic_message(ERROR_DIRNOTWRITABLE($dir));
    }
    $dir = "$absroot"; # XXX as of now absroot must be writable. need to fix.
    if (!(check_writable($dir))) {
        generic_message(ERROR_DIRNOTWRITABLE($dir));
    }
    $dir = "$absroot/OLDGROUPS";
    if (!(check_writable($dir))) {
        generic_message(ERROR_DIRNOTWRITABLE($dir));
    }

    /* create a config file for the user to copy to ABSROOT */
    write_config($G, $opts, $desc, "comolive.conf");

    /*  create the public and admin site directories  */
    $gm = new GroupManager($G);
    $gm->addGroup('public');
    $gm->deploy();

    $m = "Configuration complete.  Copy the comolive.conf file " .
         "to the web root.<br><pre>" . 
         "mv $absroot/config/comolive.conf $absroot/<br></pre>" .
         "You can make changes to the config file by " . 
         "editing comolive.conf<br>" . 
         "Click <a href=$webroot/>here</a> when you have moved the file";
    generic_message($m);
}

/*  Function to write the config file.  Changes to comolive.conf should
 *  be made here 
 */
function write_config($G, $opts, $desc, $outfile) {
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
    "    \$GLOBAL['REV'] = " . $G['REV'] . ";\n\n";

    foreach ($opts as $opt) {
        if ($opt == 'PYTHON' || $opt == 'DOT')
            continue; /* set manually below */

        $c .= comment($desc[$opt]);
        if ($opt == 'CONVERT')
            $c .= "    \$GLOBAL['".$opt."'] = \"" . $G[$opt] .
                  " -density 200x200 -resize 600x450\";\n\n";
        else
            $c .= "    \$GLOBAL['".$opt."'] = \"" . $G[$opt] . "\";\n\n";
    }
    
    $c .= "     /*\n" .
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
 *  Function to convert the description of vars to print nicely in the config 
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
?>
