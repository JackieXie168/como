<!--  $Id$  -->

<?php
    include("../include/framing.php");
    include("../include/helper-messages.php");
    $header = simple_header("../");
    $footer = simple_footer();

    if (!file_exists("../comolive.conf")) {
	$mesg = "Please click <a href=../config/>here</a> to create a ";
        $mesg .= "comolive.conf file<br>"; 
        $generic_message = $mesg;
        include("../html/generic_message.html");
	exit; 
    }

    require_once "../comolive.conf";

    if (!(isset ($G)))
	$G = init_global();

    $ALLOWCUSTOMIZE = $G['ALLOWCUSTOMIZE'];
    $NODEDB = $G['NODEDB'];
    $groupfname = $NODEDB . "/groups.lst";
    $nodefname = $NODEDB . "/nodelist.lst";

    /*
     *  $allgroups is a 2d array containing 
     *  array[n][x] where x is 
     *  [0] acutal filename of the group file, e.g. default.lst
     *  [1] Pretty name define as the group name
     *  Array 
     *	[0] => Array
     *       [0] => default.lst
     *       [1] => Como Nodes
     */ 
    if (file_exists($groupfname)) {
        $tmp = file($groupfname);
        /*  Put public at beginning of the array  */
        $all_groups[0] = "public";
        $i = 1;
        /** 
         * Need to do it this way because of the newline chars at end
         */
        foreach ($tmp as $site) {
            $all_groups[$i] = trim($site);
            $i++;
        }

        /*  Count of all members in groups  */
        $group_count = array();
        foreach ($all_groups as $val) {
            $group_count[$val] = 0;
        }
    }
     
    /*  Build the node array  */
    $node_array = array();
    $n = $x = 0;
    $nodelist = "";
    if (file_exists($nodefname)) {
        $nodelist = file($nodefname);
    }
    /*  Read the directory and populate node array  */
    /*  Start at 1 to skip the header  */
    for ($i = 1; $i < count($nodelist); $i++) {
        list($name, $comonode, $loc, $iface, $comment, $groups) 
            = split(';;', $nodelist[$i]);
        list ($host, $port) = split (":", $comonode);
        /*  Build the member list  */
        $memberlist = explode("*;*", $groups);
        $x = 0;
        foreach ($memberlist as $site) {
            if ($site == "") {
                break;
            }
            $nodes = array();
            $nodes['comonode'] = $comonode;
            $nodes['host'] = $host;
            $nodes['port'] = $port;
            $nodes['name'] = 
            "<a href=dashboard.php?comonode=$comonode>$name</a>";
            $nodes['location'] = $loc;
            $nodes['interface'] = $iface;
            $nodes['comment'] = $comment;
            $nodes['delnode'] = "";

            if ($ALLOWCUSTOMIZE) {
                /*  This is to delete the router  */
                $tmp = "";
                $tmp = "<a href=managenode.php?action=delete";
                $tmp = $tmp . "&group=$site";
                $tmp = $tmp . "&comonode=$comonode>Remove</a>";
                $nodes['delnode'] = $tmp;
            }
            if ($ALLOWCUSTOMIZE) {
                /*  This is to modify the group  */
                $tmp = "";
                $tmp = "<a class=grouplink href=nodeview.php?";
                $tmp = $tmp . "comonode=$comonode>";
                $tmp = $tmp . "Modify</a>";
                $nodes['modify'] = $tmp;
            } 
            $node_array[$site]['nodes'][$group_count[$site]] = $nodes;
            $node_array[$site]['delgroup'] = "";
            if ($ALLOWCUSTOMIZE) {
                /*  This is to delete the group  */
                $tmp = "";
                $tmp = "<a class=grouplink href=managenode.php?";
                $tmp = $tmp . "action=groupdel&group=$site>";
                $tmp = $tmp . "Remove</a>";
                $node_array[$site]['delgroup'] = $tmp;
            } 
            $x++;
            $group_count[$site]++;
        }
    }
    if (file_exists($groupfname)) {
        foreach ($group_count as $site => $num) {
            if ($group_count[$site] == 0) {
                $nodes = array();
                /*  There are no nodes defined in this group  */
                $mes = "No Como Nodes are defined";
                $mes = $mes . " in this group";
                $nodes['name'] = $mes;
                $nodes['host'] = "";
                $nodes['port'] = "";
                $nodes['location'] = "";
                $nodes['interface'] = "";
                $nodes['comment'] = "";
                $nodes['delnode'] = "";
                $node_array[$site]['nodes'][$group_count[$site]] = $nodes;
                if ($ALLOWCUSTOMIZE) {
                    /*  This is to delete the group  */
                    $tmp = "";
                    $tmp = "<a class=grouplink href=managenode.php?";
                    $tmp = $tmp . "action=groupdel&group=$site>";
                    $tmp = $tmp . "Remove</a>";
                    $node_array[$site]['delgroup'] = $tmp;
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

    include ("../html/nodelist.html");
?>
