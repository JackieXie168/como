<!--  $Id$  -->
<?
    require_once("comolive.conf");
    require_once("class/node.class.php");

    /*  get the node hostname and port number */
    if (isset($_GET['comonode'])) {
	$comonode = $_GET['comonode'];
    } else {
	print "sysinfo.php requires the comonode=host:port arg passed to it";
	exit;
    }

    $node = new Node($comonode, $TIMEPERIOD, $TIMEBOUND);

    /*
     * GET input variables
     */
    include("include/getinputvars.php.inc");
    include ("class/query.class.php");

    $query = new Query($stime, $etime, $RESULTS, $GNUPLOT, $CONVERT, $RESOLUTION);
    $query_string = $query->get_query_string($module, $format, $http_query_string);
    $data = $query->do_query ($node->comonode, $query_string);
    if (!$data[0]) {
	print "<p align=center>"; 
	print "Sorry but this module is not available <br>";
	print "on this node at the moment.<br>";
    } else {   
	$filename = $query->plot_query($data[1], $node->comonode, $module);
    } 
?>

<html>
  <head>
    <link rel="stylesheet" type="text/css" name="como" href="css/comolive.css">
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
  <br>
  <body>
    <object>
   
      <div id="nav">
	<ul>
            <?
            /*  This is the number of buttons per row  */
            $NUMLINKS = 20;
	    $special = "ports";
	    $notshown[0] = "tuple"; 
	    $notshown[1] = "topports"; 
	    $notshown[2] = "topdest"; 
	    $notshown[3] = "alert"; 
	    $notshown[4] = "AP"; 
	    $SKIP_MODULES = 5; 

            $allmods = array_keys($node->loadedmodule); 
            
            for ($i = 0; $i < count($allmods); $i++) {
                if (($i % $NUMLINKS == 0) && ($i != 0))
                    print "</ul>\n<ul>\n";

		$skip = 0; 
		for ($j = 0; $j < $SKIP_MODULES; $j++) { 
		     if ($allmods[$i] == $notshown[$j]) 
			$skip = 1; 
		} 
			
                if ($module == $allmods[$i]) {
		    print "<li class=\"selected\">$allmods[$i]</li>";
                } else if (!$skip) {
		    print "<li><a href=\"mainstage.php?";
		    print "comonode=$node->comonode&module=$allmods[$i]&";
		    if ($allmods[$i] == $special) {
			$duration = $node->etime - $node->stime; 
			print "source=tuple&interval=$duration&"; 
		    } 
                    print "filter={$node->loadedmodule[$allmods[$i]]}&";
		    print "stime=$node->stime&etime=$node->etime\">";
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
	    if ($USEFLASH == false || $module == "ports"){
		print "<img src=$filename.jpg>";
	    } else {
		print "<!-- Using flash here -->";
		include("flash/zooming.php");
            }
	}


        ?>
      Download: [<a href=<?=$filename?>.jpg>JPG</a>]
                [<a href=<?=$filename?>.eps>EPS</a>]
      </center>
    </object>
  </body>
</html>
