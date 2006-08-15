<!--  $Id$  -->

<?php
    /* 
     * this is the entry page to the CoMolive! site. show the banner
     * and add the usual html header stuff. 
     */
    require_once ("comolive.conf");
    require_once("include/framing.php");
    if (!(isset ($G)))
	$G = init_global();
    /** get the all the groups that have been created  
    *   They should be located in the db directory and 
    *   have a lst extension
    */
  
    $ALLOWCUSTOMIZE = $G['ALLOWCUSTOMIZE'];
    $dadir = $G['NODEDB'];
    $handle=opendir("$dadir");
    /**
     *  $allgroups is a 2d array containing 
     *  array[n][x] where x is 
     *  [0] acutal filename of the group file, e.g. default.lst
     *  [1] Pretty name define as the group name
     *  Array 
     *	[0] => Array
     *       [0] => default.lst
     *       [1] => Como Nodes
     */ 
    $all_groups = array();
    $node_array = array();
    $n = $x = 0;
    /*  Read the directory and populate node array  */
    while (false!==($filez= readdir($handle))) {
        if ($filez!= "." && $filez!= ".." && ereg (".*\.lst$", $filez)) {
	    if (file_exists("{$G['NODEDB']}/$filez")) {
	        $desc = file ("{$G['NODEDB']}/$filez");
                $group = trim($desc[0]);
		$all_groups[$n++] = trim($desc[0]);
		$nodes = array();
		$x = 0;
                /*  Start at 1 because the file has group info on line 1  */
                for ($i = 1; $i < count($desc); $i++) {
		    /*  There are nodes in this group  */
                    if (count($desc) != 2) {
			list($name, $comonode, $loc, $iface, $comment) 
			    = split(';;', $desc[$i]);
			list ($host, $port) = split (":", $comonode);
			$nodes[$x]['comonode'] = $comonode;
			$nodes[$x]['host'] = $host;
			$nodes[$x]['port'] = $port;
			$nodes[$x]['name'] = $name;
			if ($name != "Name")
			    $nodes[$x]['name'] = 
			    "<a href=dashboard.php?comonode=$comonode>$name</a>";
			$nodes[$x]['location'] = $loc;
			$nodes[$x]['interface'] = $iface;
			$nodes[$x]['comment'] = $comment;
			$nodes[$x]['delnode'] = "";
			if (($ALLOWCUSTOMIZE) && ($i != 1)) {
			    /*  This is to delete the router  */
			    $tmp = "";
			    $tmp = "<a href=managenode.php?action=delete";
			    $tmp = $tmp . "&group=$filez";
			    $tmp = $tmp . "&comonode=$comonode>Remove</a>";
			    $nodes[$x]['delnode'] = $tmp;
			}
			$x++;
		    } else {
			/*  There are no nodes defined in this group  */
                        $mes = "No Como Nodes are defined";
                        $mes = $mes . " in this group";
                        $nodes[0]['name'] = $mes;
			$nodes[$x]['host'] = "";
			$nodes[$x]['port'] = "";
			$nodes[$x]['location'] = "";
			$nodes[$x]['interface'] = "";
			$nodes[$x]['comment'] = "";
			$nodes[$x]['delnode'] = "";
                    }
                    
		}
		$node_array[$group]['nodes'] = $nodes;
		$node_array[$group]['filename'] = $filez;
		$node_array[$group]['delgroup'] = "";
                if ($ALLOWCUSTOMIZE) {
                    /*  This is to delete the group  */
                    $tmp = "";
                    $tmp = "<a class=grouplink href=managenode.php?";
                    $tmp = $tmp . "action=groupdel&group=$filez>";
                    $tmp = $tmp . "Remove</a>";
		    $node_array[$group]['delgroup'] = $tmp;
 
                }
	    } 
        }
    }

    $header = do_header(NULL, $G); 
    $footer = do_footer(NULL); 
    /**  
     *  Organize the hosts by group and display 
     */
    $numnodes = count($node_array);
    /*  If there are no nodes defined, create a blank array with a message  */
    if ($numnodes < 1) {
	$all_groups[0] = "CoMo Nodes";
	$mes = "No Como Nodes have been saved";
	$nodes = array();
	$node_array = array();
	$nodes[0]['name'] = $mes;
	$nodes[$x]['host'] = "";
	$nodes[$x]['port'] = "";
	$nodes[$x]['location'] = "";
	$nodes[$x]['interface'] = "";
	$nodes[$x]['comment'] = "";
	$nodes[$x]['delnode'] = "";
	$node_array[$all_groups[0]]['nodes'] = $nodes;
	$node_array[$all_groups[0]]['delgroup'] = "";
	$node_array[$all_groups[0]]['filename'] = "";

    }

    include ("html/nodelist.html");
?>
