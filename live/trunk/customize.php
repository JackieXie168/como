<?php
    $pagetitle="Customize CoMo";
    $includebanner=0;
    include ("include/header.php.inc");
    require_once("comolive.conf");
    require_once("class/node.class.php");
  
    if (!($ALLOWCUSTOMIZE)){
        print "Customization of CoMoLive is NOT allowed<br>";
        print "Please check your comolive.conf file<br>";
        exit;

    }

    /* get the node hostname and port number */
    if (isset($_GET['comonode'])) {
	$comonode = $_GET['comonode'];
    } else {
	print "{$_SERVER['SCRIPT_FILENAME']}";
        print " requires the comonode=host:port arg passed to it";
	exit;
    }
    $node = new Node($comonode,$TIMEPERIOD, $TIMEBOUND);

    include ("include/getinputvars.php.inc");
    if ($node->status == "FAIL") {
        /*
         * query failed. write error message and exit
         */
        include("include/header.php.inc");
    ?>
        <div id=content>
          <div class=graph">
          <br><br><center>
            Sorry but the requested CoMo node is not <br>
            available at the moment. Please try another time.<br><br>
          </div>
        </div>
    <?php
        include("include/footer.php.inc");
        exit;
    }
    $mainmods = $node -> GetModules("gnuplot");
    $secmods = $node -> GetModules("html");

    if (isset($_GET['action']))
	$action = $_GET['action'];
    else
	$action = "NORM";
/*  Write out new config file  */
    if ($action == "submit"){
	$val = explode ("&", $_SERVER['QUERY_STRING']);
	$secfile = "sec_mods";
	$mainfile = "main_mods";
	for ($i=0;$i<count($val);$i++){
	    if (strstr($val[$i], "mainmods")){
		$mainfile = $mainfile . ";;";
		$mod = explode ("=", $val[$i]);
		$mainfile = $mainfile . $mod[1];
	    }
	}
	$mainfile = $mainfile . "\n";
	for ($i=0;$i<count($val);$i++){
	    if (strstr($val[$i], "secmods")){
		$secfile = $secfile . ";;";
		$mod = explode ("=", $val[$i]);
		$secfile = $secfile . $mod[1];
	    }
	}
	$secfile = $secfile . "\n";
	if ($fh = fopen ("$NODEDB/$comonode.conf", "w")) {
	    fwrite ($fh, $mainfile);
	    fwrite ($fh, $secfile);
	    fclose ($fh);
	}
    }

    /*  Read config file  */
    if (file_exists("$NODEDB/$comonode.conf")){
        $dafile = file ("$NODEDB/$comonode.conf");
	for ($i=0;$i<count($dafile);$i++){
	    if (strstr($dafile[$i], "sec_mods")) {
                $secfile = $dafile[$i];
	    }
	    if (strstr($dafile[$i], "main_mods")) {
                $mainfile = $dafile[$i];
	    }
        }
    }
?>
<style>
    body { 
	font-family : "lucida sans unicode", verdana, arial;
        font-size : 9pt; 
        margin : 0; 
        padding : 0;
    }
    table, tr, td {
	background-color : #DDD;
	font-family : "lucida sans unicode", verdana, arial;
        font-size : 9pt;
        width : 95%;
    }
    a, a:visited { 
	color : #475677; 
        text-decoration: none;
    }
    .nvtitle {
        font-weight : bold;  
	font-size: 10pt; 
        padding-bottom: 3px;
        color: #475677;
        text-align : center;
    }
    .nvcontent {
	background-color : #FFF;
        padding : 0px 10px 0px 10px ;
    }
    .nvheader {
	background-color : #FFF;
        padding : 0px 10px 0px 10px ;
        font-size : 20px;
        text-align : center;
    }


</style>

<body>
<form action="customize.php" method="GET">
<table class=customize>
  <tr>
    <td class=nvheader>
      Configuration File for : <?=$comonode?>
    </td>
  </tr>
  <tr>
    <td class=nvtitle>
      Main Window 
    </td>
  </tr>
  <tr>
    <td class=nvcontent>
      Please select the main plot<br>
      <?php
	  for ($i=0;$i<count($mainmods);$i++) {
	      print "<input name=mainmods ";
	      if (strstr($mainfile, $mainmods[$i]))
		  print " checked ";
	      print "type=checkbox value=$mainmods[$i]>";
	      print "$mainmods[$i]<br>\n";
	  }
      ?>
    </td>
  </tr>
  <tr>
    <td class=nvtitle>
        Secondary Window
    </td>
  <tr>
    <td class=nvcontent>
         Please select the modules that you want shown <br>
        <?php
            for ($i=0;$i<count($secmods);$i++) {
                print "<input name=secmods ";
                if (strstr($secfile, $secmods[$i]))
		    print " checked ";
		print "type=checkbox value=$secmods[$i]>";
                print "$secmods[$i]<br>\n";
            }
        ?>
            <input type=hidden name=comonode value=<?=$comonode?>>
            <input type=hidden name=action value=submit>
    </td>
  </tr>
  <tr>
    <td style=text-align:center;>
            <input type=submit value="Save Changes">
            <input type=submit value="Finished" OnClick=window.close(this);>
    </td>
  </tr>
</table>
</form>
</body>

