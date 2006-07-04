<!--  $Id$  -->

<?php
    require_once ("comolive.conf");
    if (!(isset($G)))
        $G = init_global();
    require_once ("class/node.class.php");
    require_once ("class/query.class.php");
    require_once ("include/getinputvars.php.inc");

    /*  get the node hostname and port number */
    if (!isset($_GET['comonode'])) {
	print "{$_SERVER['SCRIPT_FILENAME']}";
	print " requires the comonode=host:port arg passed to it";
	exit;
    }

    $comonode = $_GET['comonode'];
    $comonode_array = split (";;", $comonode);

    /* Check if this is a distributed query
     * Eventually this will be a como module, however, we will hard
     * code it to get an idea of our future direction
     * 
     * XXX very experimental code. (i.e. doesn't run at the moment)
     */
    if (count($comonode_array) > 1) {
	include "distributed_query.php"; 
	exit;
    } 

    /*  Normal single node query  */
    $node = new Node($comonode, $G);
    $input_vars = init_env($node);
    $module = $input_vars['module'];
    $fiter = $input_vars['filter'];
    $end = $input_vars['end'];
    $start = $input_vars['start'];
    $format = $input_vars['format'];

    $http_query_string = $_SERVER['QUERY_STRING'] . "&filter=" . $node -> modinfo[$module]['filter'];
    $query = new Query($start, $end, $G);
    $query_string = $query->get_query_string($module, $format, $http_query_string);
    $data = $query->do_query($comonode, $query_string);

    if (!$data[0]) {
	print "<p align=center>"; 
	print "Sorry but this module is not available <br>";
	print "on this node at the moment.<br>";
    } else {   
	$filename = $query->plot_query($data[1], $comonode, $module);
    } 
?>

<html>
  <head>
    <link rel="stylesheet" type="text/css" name="como" href="css/live.css">
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
    <object>
   
      <div id="nav">
	<ul>
            <?
            /*  This is the number of buttons per row  */
            $NUMLINKS = 6;
/*  commenting out to find what breaks  */
#	    $special = "ports";

            /*  Use the config file to decide how many modules to show  */
            #$allmods = array_keys($node->loadedmodules); 
            $allmods = $node->getConfig("main");
	    #print_r($allmods);
            
            for ($i = 0; $i < count($allmods); $i++) {
                if (($i % $NUMLINKS == 0) && ($i != 0))
                    print "</ul>\n<ul>\n";

                if ($module == $allmods[$i]) {
		    print "<li class=\"selected\">$allmods[$i]</li>";
                } else {
		    print "<li><a href=\"loadcontent.php?";
#		    print "comonode=$node->comonode&module=$allmods[$i]&";
		    print "comonode=$comonode&module=$allmods[$i]&";
/*  Commenting this out because I don't know what it is...  */
#		    if ($allmods[$i] == $special) {
#			$duration = $node->end - $node->start; 
#			print "source=tuple&interval=$duration&"; 
#		    } 
                    print "filter={$node->modinfo[$allmods[$i]]['filter']}&";
/*  Commenting out next line and replacing with start from GEt
 *  Need to see if this breaks things.
 *  This line was originally intended to grab the individual
 *  module start time
 */
#		    print "start=$node->start&end=$node->end\">";
		    print "start=$start&end=$end\">";
		    print "$allmods[$i]</a></li>\n";
                }
            }

            ?>
	</ul>
      </div>
      <center>

        <? 
        /*   <img src="<?=$filename?>.jpg">  */
          /*  This is where we print the image  */
        $fullname = $query->getFullfilename($module) . ".jpg";
	if (file_exists("$fullname")) {
	    if ($G['USEFLASH'] == false || $module == "ports"){
		print "<img src=$filename.jpg>";
	    } else {
		print "<!-- Using flash here -->";
		include("flash/zooming.php");
            }
	} else {
	    print "<img src=images/blankplot.jpg>";
        }


        ?>
      </center>
      <center>
      Download: [<a href=<?=$filename?>.jpg>JPG</a>]
                [<a href=<?=$filename?>.eps>EPS</a>]
      </center>
    </object>
  </body>
</html>
