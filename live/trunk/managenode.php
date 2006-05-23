<?
    /*  managenode.php 
     * 
     *  This file will require the comonode=host:port arg passed to it  
     *
     *  $Id$  
     */
    require_once("comolive.conf");
    $G = init_global();
    $ALLOWCUSTOMIZE = $G['ALLOWCUSTOMIZE'];
    $NODEDB = $G['NODEDB'];
    $ABSROOT = $G['$ABSROOT'];
    require_once("class/node.class.php");

    /*  Don't allow entrace without customization priviledge  */
    if (!$ALLOWCUSTOMIZE) {
        header("Location: index.php");
        exit;
    }

    if (isset ($_GET['group']))
        $group = $_GET['group'];
    else
        $group = "";

    $nodefile = "$group";

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
        $node = new Node($comonode, $G);
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
	  if (!file_exists($NODEDB)) {
	    /*  Attempt to create the db directory  */
	    if (!(system ("mkdir $ABSROOT/$NODEDB"))){
	      print "Directory $NODEDB, as specified in comolive.conf, ";
	      print "is not writable by webserver<br>";
	      print "Please create this directory and make ";
	      print "it writable by the webserver<br><br>";
	      print "$ABSROOT/$NODEDB";
	      exit;
	    }
	  }
	  if (!(file_exists("$NODEDB/$nodefile"))) {
	    if (!($fh = fopen("$NODEDB/$nodefile", "w"))){
	      print "Unable to open file $NODEDB/$nodefile<br>";
	      exit;
	    }
    
	    $tofile = "Name;;CoMo Name:Port;;Location;;Interface;;Comments;;\n";
    	    if (fwrite ($fh, $tofile) === FALSE){
    		print "$NODEDB/$nodefile not writable";
    		exit;
    	    }
    	    fclose($fh);
	  } else {
    	    $fh = fopen("$NODEDB/$nodefile", "a");

    	    $tmp = $node -> nodename . ";;" ;
    	    $tmp = $tmp . $node -> comonode . ";;" ;
    	    $tmp = $tmp . $node -> nodeplace . ";;" ;
            $tmp = $tmp . $node -> linkspeed . ";;" ;
    	    $tmp = $tmp . $node -> comment. "\n" ;
    	    $tofile = $tmp;
    	    if (fwrite ($fh, $tofile) === FALSE) {
	      print "Unable to write to file $nodefile<br>";
	      exit;
    	    } else {
	      fclose($fh);
	      header("Location: index.php");
    	    }
	  }
        } 
      }
      if ($action == "delete"){
        $datafile = file ("$NODEDB/$nodefile");
        $tofile = "";
        for ($i=0;$i<count($datafile);$i++){
            if ($i==0) {
    	        $tofile = $tofile . $datafile[$i];
            } else {
		$val = explode (";;", $datafile[$i]);
		if ($comonode != $val[1]){
		    $tofile = $tofile . $datafile[$i];
		}
            }
        }
	$fh = fopen("$NODEDB/$nodefile", "w+");
        if (fwrite ($fh, $tofile) === FALSE) {
	  print "Unable to write to file $nodefile<br>";
	  exit;
	} else {
	  fclose($fh);
	  header("Location: index.php");
	}
      }
      if ($action == "groupdel"){
          system ("rm -rf $NODEDB/$group");
	  header("Location: index.php");
      }
    ?>

  </object>
  </body>
</html>
