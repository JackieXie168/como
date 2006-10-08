<?
     /*  $Id$  */
    require_once ("../comolive.conf");
    require_once ("../class/node.class.php");
    require_once ("../include/framing.php"); 

    $G = init_global();
    $ALLOWCUSTOMIZE = $G['ALLOWCUSTOMIZE'];
    $NODEDB = $G['NODEDB'];
    $ABSROOT = $G['ABSROOT'];

    $header = do_header(NULL, 1);
    $footer = do_footer(NULL);

    /*  Don't allow entrace without customization priviledge  */
    if (!$ALLOWCUSTOMIZE) {
        header("Location: index.php");
        exit;
    }
    /*  get the node hostname and port number */
    $comonode = "";
    if (isset($_GET['comonode']))
	$comonode = $_GET['comonode'];

    $group = "";
    if (isset ($_GET['group']))
        $group = $_GET['group'];

    $nodefile = "$group";

    $action = "add";
    if (isset ($_GET['action']))
        $action = $_GET['action'];

    /*  Add a config file or just an entry  */
    if ($action == "add") {
        $node = new Node($comonode, $G);
        if (!($node->status)){
	    /*
	     * query failed. write error message and exit
	     */
            include ("../html/node_failure.html");
	    exit;
        } 
       
	/*  Attempt to create the db directory  */
	if (!file_exists($NODEDB)) {
	    if (!(system ("mkdir $ABSROOT/$NODEDB"))){
		$mes = "NOTICE<br>Directory $NODEDB, as specified ";
                $mes = $mes . "in comolive.conf, ";
		$mes = $mes . "is not writable by the webserver<br>";
		$mes = $mes . "Please create this directory and make ";
		$mes = $mes . "it writable by the webserver<br><br>";
		$generic_message = $mes;
		include ("../html/generic_message.html");
		exit;
	    }
	}
        /*  Try to open the file for writing if it doesn't exist  */
	if (!(file_exists("$NODEDB/$nodefile"))) {
            /*  The file doesn't exist, create a message  */
	    if (!($fh = fopen("$NODEDB/$nodefile", "w"))){
		$mes = "NOTICE<br>Unable to open file for writing";
                $mes = $mes . "<br>$NODEDB/$nodefile<br>";
		$mes = $mes . "Please check permissions<br>";
		$mes = $mes . "on this directory and the file.<br>";
		$generic_message = $mes;
		include ("../html/generic_message.html");
		exit;
	    }
            /*  Create the config file  */
	    $tofile = "Name;;CoMo Name:Port;;Location;;Interface;;Comments;;\n";
            /*  Write data to the file  */                               
	    fwrite ($fh, $tofile);
	    fclose($fh);
	} else {
            /*  The file does exist, append new data to it  */
    	    if (($fh = fopen("$NODEDB/$nodefile", "a")) === FALSE) {
		$mes = "NOTICE<br>Unable to open file for writing";
                $mes = $mes . "<br>$NODEDB/$nodefile<br>";
		$mes = $mes . "Please check permissions<br>";
		$mes = $mes . "on this directory and the file.<br>";
		$generic_message = $mes;
		include ("../html/generic_message.html");
		exit;
            }

    	    $tmp = $node -> nodename . ";;" ;
    	    $tmp = $tmp . $node -> comonode . ";;" ;
    	    $tmp = $tmp . $node -> nodeplace . ";;" ;
            $tmp = $tmp . $node -> linkspeed . ";;" ;
    	    $tmp = $tmp . $node -> comment. "\n" ;
    	    $tofile = $tmp;
    	    fwrite ($fh, $tofile);
	    fclose($fh);
	    header("Location: index.php");
        }
    }
    /*  Delete a entry in the config file matching comonode  */
    if ($action == "delete") {
        $datafile = file ("$NODEDB/$nodefile");
        $tofile = "";
        for ($i = 0; $i < count($datafile); $i++){
            if ($i == 0) {
    	        $tofile = $tofile . $datafile[$i];
            } else {
		$val = explode (";;", $datafile[$i]);

		if ($comonode != $val[1]){
		    $tofile = $tofile . $datafile[$i];
		}
            }
        }
	if (($fh = fopen("$NODEDB/$nodefile", "w+")) === FALSE) {
	    $mes = "NOTICE<br>Unable to open file for writing";
	    $mes = $mes . "<br>$NODEDB/$nodefile<br>";
	    $mes = $mes . "Please check permissions<br>";
	    $mes = $mes . "on this directory and the file.<br>";
	    $generic_message = $mes;
	    include ("../html/generic_message.html");
	    exit;
        }
        fwrite ($fh, $tofile);
	fclose($fh);
	header("Location: index.php");
    }
    if ($action == "groupdel"){
	system ("rm -rf $NODEDB/$group");
	header("Location: index.php");
    }
    ?>

  </object>
  </body>
</html>
