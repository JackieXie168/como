<?
    /*  managenode.php 
     * 
     *  This file will require the comonode=host:port arg passed to it  
     *
     *  $Id$  
     */
    require_once("comolive.conf");
    require_once("class/node.class.php");
    $nodefile = "nodes.lst";

    /*  get the node hostname and port number */
    if (isset($_GET['comonode'])){
        $comonode = $_GET['comonode'];
    }else{
        print "This file requires the comonode=host:port arg passed to it";
        exit;
    }
    if (isset ($_GET['action']))
        $action = $_GET['action'];
    else
        $action = "add";

    if ($action == "add") {
        $node = new Node($comonode, $TIMEPERIOD, $TIMEBOUND);
        if ($node->status == "FAIL"){
    	/*
    	 * query failed. write error message and exit
    	 */
            $includebanner=1;
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
        } else {
     
    	if (!(file_exists("$NODEDB/$nodefile"))) {
    	    if (!($fh = fopen("$NODEDB/$nodefile", "w"))){
    		print "Unable to open file $NODEDB/$nodefile";
    		exit;
    	    }
    
    	   $tofile = "Node Name:Port;Location;Interface;Comments;\n";
    	    if (fwrite ($fh, $tofile) === FALSE){
    		print "$NODEDB/$region.lst not writable";
    		exit;
    	    }
    	    fclose($fh);
    	} else {
    	    $fh = fopen("$NODEDB/$nodefile", "a");
#                $var = split (":", $node -> comonode);
#                $name = $var[0]; 
#                $port = $var[1]; 
    	    $tmp = $node -> comonode . ";" ;
    	    $tmp = $tmp . $node -> nodeplace . ";" . $node -> linkspeed . ";" ;
    	    $tmp = $tmp . $node -> comment. "\n" ;
    	    $tofile = $tmp;
    	    if (fwrite ($fh, $tofile) === FALSE) {
    		print "Unable to write to file $nodefile<br>";
    		exit;
    	    } else {
    		header("Location: index.php");
    	    }
    	    fclose($fh);
            }
        } 
    }
    if ($action == "delete"){
        $datafile = file ("$NODEDB/$nodefile");
        $tofile = "";
        for ($i=0;$i<count($datafile);$i++){
            $val = explode (";", $datafile[$i]);
            if ($comonode != $val[0]){
    	        $tofile = $tofile . $datafile[$i];
            }
        }
	$fh = fopen("$NODEDB/$nodefile", "w+");
        if (fwrite ($fh, $tofile) === FALSE) {
            print "Unable to write to file $nodefile<br>";
	    exit;
	} else {
	    header("Location: index.php");
	}
	fclose($fh);
    }
    ?>

  </object>
  </body>
</html>
