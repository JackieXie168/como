<?php
    /* $Id$ */
    require_once ("../comolive.conf");
    if (!(isset($G)))
        $G = init_global();
    require_once ("../class/node.class.php");
    require_once ("../class/query.class.php");
    require_once ("../include/getinputvars.php.inc");
    require_once "../class/nodedb.class.php";

    /*  get the node hostname and port number */
    if (!isset($_GET['comonode'])) {
	print "{$_SERVER['SCRIPT_FILENAME']}";
	print " requires the comonode=host:port arg passed to it";
	exit;
    }

    $comonode = $_GET['comonode'];

    /* Check if this is a distributed query
     * Eventually this will be a como module, however, we will hard
     * code it to get an idea of our future direction
     * 
     * XXX very experimental code. (i.e. doesn't run at the moment)
     */
    /*
    $comonode_array = split (";;", $comonode);
    if (count($comonode_array) > 1) {
	include "distributed_query.php"; 
	exit;
    }
    */

    // Check we have permission to query this node
    $db = new NodeDB($G);
    if (! $db->hasNode($comonode)) {
        print "Sorry, but you do not have permission to query " .
            "the CoMo node at $comonode<br>\n";
        exit;
    }

    /*  Normal single node query  */
    $node = new Node($comonode, $G);
    $input_vars = init_env($node);
    $module = $input_vars['module'];
    $filter = $input_vars['filter'];
    $end = $input_vars['end'];
    $start = $input_vars['start'];
    $format = $input_vars['format'];

    $http_query_string = $_SERVER['QUERY_STRING'] . "&filter=" . $node -> modinfo[$module]['filter'];
    $query = new Query($start, $end, $G);
    $query_string = $query->get_query_string($module, $format, $http_query_string);

    if ($format == 'gnuplot') {
        $data = $query->do_query($comonode, $query_string);
        if (!$data[0]) {
            print "<p align=center>"; 
            print "Sorry but this module is not available <br>";
            print "on this node at the moment.<br>";
        }
	$filename = $query->plot_query($data[1], $comonode, $module);
    }
?>
<html>
  <head>
    <link rel="stylesheet" type="text/css" name="como" href="../css/live.css">
<style type="text/css">
      #nav ul {
	border-bottom: 1px solid; 
        padding:0px;
        background-color:white;
        font-size:9pt;
	margin-left: 50px;
	margin-right: 10px;
	margin-bottom: 0px;
      }
      #nav ul li {
        display:inline;
        color:black;
        border-style:none;
	border-top: 1px solid #ddd; 
	border-right: 1px solid #ddd; 
	border-left: 1px solid #ddd; 
      }
      #nav ul li.selected {
        background-color:#DDD;
        border-style:none;
	border-top: 1px solid #ddd; 
	border-right: 1px solid #ddd; 
	border-left: 1px solid #ddd; 
	padding-left: 1em;
	padding-right: 1em;
      }
      #nav a {
        color:black;
        background-color:#FFF;
        text-decoration:none;
        padding-left:1em;
        padding-right:1em;
      }
      #nav ul li a:hover {
        border-style:none;
        background-color:#DDD;
      }
</style>
      <div id="nav">
	<ul>
            <?php
            /*
             * Build the list of tabs
             */

            /*  This is the number of buttons per row  */
            $NUMLINKS = 6;

            /*
             * supported formats XXX cleaner design needed
             */
            function is_supported($fmt) {
                $supported_formats = array('gnuplot'=>1, 'conversation_graph'=>1);
                return array_key_exists($fmt, $supported_formats);
            }

            /*  Use the config file to decide how many modules to show  */
            $i = 0;
            foreach ($node->getConfig('main') as $m) {
                foreach ($node->getModuleFormats($m) as $fmt) {
                    # only pick supported formats
                    if (! is_supported($fmt))
                        continue;

                    if (($i % $NUMLINKS == 0) && ($i != 0))
                        print "</ul>\n<ul>\n";
                    $i++;

                    $name = $m;
                    if ($fmt == 'conversation_graph')
                        $name = $m.' (graph)';
                    if ($module == $m && $format == $fmt) {
                        print "<li class=\"selected\">$name</li>";
                    } else {
                        print "<li><a href=\"loadcontent.php?";
                        print "comonode=$comonode&module=$m&";
                        print "format=$fmt&";
                        print "filter={$node->modinfo[$m]['filter']}&";
                        print "start=$start&end=$end\">";
                        print "$name</a></li>\n";
                    }
                }
            }

            ?>
	</ul>
      </div>
      <center>

        <?php 
        /*   <img src="<?php echo $filename?>.jpg">  */
        /*  This is where we print the image  */
        if ($format == 'gnuplot') {
            $fullname = $query->getFullfilename($module) . ".jpg";
            if (file_exists("$fullname")) {
                if ($G['USEFLASH'] == false || $module == "ports"){
                    print "<img src=$filename.jpg>";
                } else {
                    print "<!-- Using flash here -->";
                    include("../flash/zooming.php");
                }
            } else {
                print "<img src=../images/blankplot.jpg>";
            }
        } else if ($format == 'conversation_graph') {
            ?>
                <applet code="ConversationView.class"
                        codebase="java"
                        width="500"
                        height="400"
                        archive="pack.jar,prefuse.jar">
                    <param name="node" value="<?= $comonode ?>">
                    <param name="module" value="<?= $module ?>">
                    <param name="filter" value="<?= $filter ?>">
                    <param name="start" value="<?= $start ?>">
                    <param name="end" value="<?= $end ?>">
                </applet>
            <?php
        }
        ?>
      </center>
      <?php if ($format == 'gnuplot') { ?>
      <center>
      Download: [<a href=<?php echo $filename?>.jpg>JPG</a>]
                [<a href=<?php echo $filename?>.eps>EPS</a>]
      </center>
      <?php } ?>
  </body>
</html>
