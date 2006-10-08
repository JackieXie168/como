<!--  $Id$  -->

<?php
    require_once "../class/node.class.php";        /* Node class */
    include_once "../comolive.conf";               /* init_global */

    if (!file_exists("../comolive.conf")) {
        print "Please create a comolive.conf file";
        exit;
    }

    /*  get the node hostname and port number */
    if (!isset($_GET['comonode'])) {
        print "This file requires the comonode=host:port arg passed to it<br>";
        print "Thanks for playing!<br><br><br><br><br><br><br>";
        exit;
    }

    $comonode = $_GET['comonode'];

    $G = init_global();

    $node = new Node($comonode, $G);
    if ($node->status == false) {
        /* cannot connect to node, fail with error */
        include ("../html/node_failure.html");
        exit;
    }

    $nodename = $node->nodename;
    $version = $node->version; 
    $online_str = gmstrftime("%a %d %b %Y %T %Z", (int) $node->start);
    $builddate = $node->builddate;

    if (isset($node->comment) && (!is_null($node->comment)))
        $comment = $node->comment; 
    else 
        $comment = ""; 

    include ("../html/sysinfo.html");
?>
