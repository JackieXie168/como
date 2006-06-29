<?php
    /*  $Id$  */
    require_once "comolive.conf";
    include_once "include/framing.php"; 
    include_once "class/node.class.php";
   
    $header = do_header(NULL, 1);
    $footer = do_footer(NULL);

    $G = init_global();
    $ALLOWCUSTOMIZE = $G['ALLOWCUSTOMIZE'];
    $NODEDB = $G['NODEDB'];

    /* Don't allow entrace without customization priviledge  */
    if (!($ALLOWCUSTOMIZE)) {
        header("Location: index.php");
        exit;
    }

    $method = "addnode";
    if (isset($_GET['method']))
        $method = $_GET['method'];

    $groupname = "default";
    if (isset($_GET['groupname']) && $_GET['groupname'] != "")
        $groupname = $_GET['groupname'];

    /* get the node hostname and port number */
    if (!isset($_GET['comonode'])) {
        $mes = "This file requires the comonode=host:port arg passed to it";
        $generic_message = $mes;
        include ("html/generic_message.html");
        exit;
    }
#    $comonode = "";
#    if (isset($_GET['comonode'])) 
    $comonode = $_GET['comonode'];


    switch ($method) { 
    case "Submit": 
	if (isset($_GET['groupselect']))
	    $groupselect = $_GET['groupselect'];
	if (isset($_GET['nodename']))
	    $nodename= $_GET['nodename'];
	if (isset($_GET['nodeplace']))
	    $nodeplace = $_GET['nodeplace'];
	if (isset($_GET['speed']))
	    $speed = $_GET['speed'];
	if (isset($_GET['comment']))
	    $comment = $_GET['comment'];

        /*  Create the default file  */
        if ($groupselect == "default") {
            $groupselect = "default.lst";
            if (!file_exists("$NODEDB/$groupselect")) 
		file_put_contents("$NODEDB/$groupselect", "CoMo Nodes\n");
        }

	$tmp = file("$NODEDB/$groupselect");
	$numlines = count($tmp);

	if (($fh = fopen("$NODEDB/$groupselect", "a")) === FALSE) {
            $mes = "NOTICE<br>File $NODEDB/$groupselect ";
            $mes = $mes . "is not writable by the webserver<br>";
            $mes = $mes . "Please check your settings and make the $NODEDB";
            $mes = $mes . " directory writable by the webserver<br><br>";
            $generic_message = $mes;
            include ("html/generic_message.html");
            exit;
        }
        $tofile = "";
        if ($numlines == 1) {
	    $tofile = "Name;;CoMo Name:Port;;Location;;Interface;;Comments;;\n";
        }

        $tofile = $tofile . $nodename . ";;" ;
        $tofile = $tofile . $comonode . ";;" ;
        $tofile = $tofile . $nodeplace . ";;" ;
        $tofile = $tofile . $speed . ";;" ;
        $tofile = $tofile . $comment . ";;\n" ;

	fwrite ($fh, $tofile);
	fclose($fh);
	header("Location: index.php");
        break; 

    case "Add Group": 
	$groupfname = ereg_replace(" ", "_", $groupname);
        if (!file_exists("$NODEDB/$groupfname")) {
	    if ($fh = fopen ("$NODEDB/$groupfname.lst", "w")) {
		$towrite = "$groupname\n";
		fwrite ($fh, $towrite);
		header ("Location: nodeview.php?comonode=$comonode");
	    } else {
		$mes = "NOTICE<br>File $NODEDB/$groupselect ";
		$mes = $mes . "is not writable by the webserver<br>";
		$mes = $mes . "Please check your settings and make the $NODEDB";
		$mes = $mes . " directory writable by the webserver<br><br>";
		$generic_message = $mes;
		include ("html/generic_message.html");
		exit;
	    }
	}
	break; 

    case "addnode": 

        /*  query the CoMo node  */
        $node = new Node($comonode,$G);
        if ($node->status == 0) { 
            include ("html/node_failure.html");
	    exit; 
	}

        /*  get the groups */
	if (!($handle = opendir("$NODEDB"))) {
	    $mes = "Directory $NODEDB, as specified in comolive.conf, ";
	    $mes = $mes . "is not writable by the webserver<br>";
	    $mes = $mes . "Please create this directory and make ";
	    $mes = $mes . "it writable by the webserver<br><br>";
	    $generic_message = $mes;
	    include ("html/generic_message.html");
	    exit;
        }
	$all_groups = array();
        $x = 0;
	while (false !== ($filez = readdir($handle))) {
	   if ($filez!= "." && $filez!= ".." && ereg (".*\.lst$", $filez)) {
               if (file_exists("$NODEDB/$filez")) {
		   $desc = file ("$NODEDB/$filez");
		   $all_groups[$x][0] = $filez;
		   $all_groups[$x][1] = $desc[0];
                   $x++;
               }
	   }
	}
	break;
    }

    include ("html/nodeview.html");
?>

