<!--  $Id$  -->

<?php
    /* 
     * XXX this code is the continuation of mainstage.php. it assumes
     *     that a lot of code has already been running in that file. 
     *     it is in a very experimental stage and doesn't run at the moment. 
     */ 

    exit; // XXX access to this file is not permitted

    $numnodes = count($comonode_array);
    $val_data = array ();
    for ($i=0;$i<count($comonode_array);$i++) {
	$node = new Node($comonode_array[$i], $G);
	$input_vars = init_env($node);
	$module = $input_vars['module'];
	$fiter = $input_vars['filter'];
	$etime = $input_vars['etime'];
	$stime = $input_vars['stime'];
	$format = $input_vars['format'];
	$http_query_string = $input_vars['http_query_string'];

	$http_query_string = "&filter=" . $node -> modinfo[$module]['filter'] . "&comonode=" . $comonode_array[$i] . "&module=" . $module;
	$query = new Query($stime, $etime, $G);
	$query_string = $query->get_query_string($module, $format, $http_query_string);
	$data = $query->do_query ($node->comonode, $query_string);
	$filename = $query->plot_query($data[1], $node->comonode, $module);

	/*  This extracts the gnuplot command  */
	$gptmp = preg_split ("/([0-9]{10})/", $data[1],2, PREG_SPLIT_DELIM_CAPTURE);
	$gnuplot_cmd = $gptmp[0];
	/*  This is the value array  */
	preg_match_all ("/[0-9]{10}.*/", $data[1], $val);
	/*  Get number of columns in data set  */
	$numcols = count (split (" ", $val[0][1]));
	for ($j=0;$j<count($val,1)-1;$j++) {
	    $tmp = split (" ", $val[0][$j]);
	    for ($k=0;$k<count($tmp)-1;$k++) {
		if (isset ($val_data[$tmp[0]][$k]))
		    $val_data[$tmp[0]][$k] += $tmp[$k+1];
		else
		    $val_data[$tmp[0]][$k] = $tmp[$k+1];
	    }
	}
    }
    /*  Get the average  */
    $keys = array_keys($val_data);
    for ($j=0;$j<count($val_data);$j++) {
	for ($k=0;$k<$numcols-1;$k++) {
	    $val_data[$keys[$j]][$k] = $val_data[$keys[$j]][$k] / $numnodes;
	}
    }
    /*  prepare the gnuplot file */
    $data[0] = 1;
    $data[1] = $gnuplot_cmd; 
    for ($j=0;$j<count($val_data);$j++) {
	$data[1] = $data[1] . $keys[$j] . " "; 
	for ($k=0;$k<$numcols-1;$k++) {
	    $data[1] = $data[1] . $val_data[$keys[$j]][$k] . " "; 
	}
	$data[1] = $data[1] . "\n"; 
    }
    /*  Put the end of the data marker here (e)  */
    /*  Need to do a better job of this once I remember how this is 
     *  generated
     */
    $data[1] = $data[1] . "e"; 
        
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
  </head>
  <body>
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
		    print "<li><a href=\"mainstage.php?";
#		    print "comonode=$node->comonode&module=$allmods[$i]&";
		    print "comonode=$comonode&module=$allmods[$i]&";
/*  Commenting this out because I don't know what it is...  */
#		    if ($allmods[$i] == $special) {
#			$duration = $node->etime - $node->stime; 
#			print "source=tuple&interval=$duration&"; 
#		    } 
                    print "filter={$node->modinfo[$allmods[$i]]['filter']}&";
/*  Commenting out next line and replacing with stime from GEt
 *  Need to see if this breaks things.
 *  This line was originally intended to grab the individual
 *  module start time
 */
#		    print "stime=$node->stime&etime=$node->etime\">";
		    print "stime=$stime&etime=$etime\">";
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
