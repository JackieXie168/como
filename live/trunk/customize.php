<?php
    $pagetitle="Customize CoMo";
    $includebanner=0;
    include ("include/header.php.inc");
    require_once("comolive.conf");
    require_once("class/node.class.php");

    include ("include/getinputvars.php.inc");
    /* get the node hostname and port number */
#phpinfo();
    if (isset($_GET['comonode'])) {
	$comonode = $_GET['comonode'];
    } else {
	print "{$_SERVER['SCRIPT_FILENAME']}";
        print " requires the comonode=host:port arg passed to it";
	exit;
    }
    $node = new Node($comonode,$TIMEPERIOD, $TIMEBOUND);

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

    if ((isset($_GET['action']))  ||  isset($_POST['action']))
	$action = $_GET['action'];
    else
	$action = "NORM";
#print_r($secmods);
#print "<pre>";
#print_r($node);
#print "</pre>";
if ($action == "submit"){
print "submitted";

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
        Da content here
    </td>
  </tr>
  <tr>
    <td class=nvtitle>
        Secondary Window
    </td>
  <tr>
    <td class=nvcontent>
         <form action="customize.php?comonode=<?=$comonode?>&action=submit" method="GET">
         Please select the modules that you want shown <br>
        <?php
            for ($i=0;$i<count($secmods);$i++) {
                print "<input name=secmods type=checkbox value=$secmods[$i]>";
                print "$secmods[$i]<br>\n";
            }
        ?>
            <input type=submit value="Save Changes">
        </form>
    </td>
  </tr>
</table>
</body>
