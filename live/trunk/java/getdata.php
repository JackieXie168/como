<?php
/* $Id$ */

chdir('..'); // go down to group's working dir

require_once ("../comolive.conf");
require_once ("../class/query.class.php");
require_once ("../class/nodedb.class.php");

if (!(isset($G)))
    $G = init_global();

// Get variables
$node = $_GET['node'];
$module = $_GET['module'];
$filter = $_GET['filter'];
$start = $_GET['start'];
$end = $_GET['end'];
$format = $_GET['format'];

// Check we have permission to query node
$db = new NodeDB($G);
if (! $db->hasNode($node)) {
    print "Permission denied\n";
    print "node=$node\n";
    print getcwd()."\n";
    exit;
}

// Proxy data from the CoMo node to the applet
$http_query_string = $_SERVER['QUERY_STRING'] . "&filter=" . $filter;
$q = new Query($start, $end, $G);
$query_string = $q->get_query_string($module, $format, $http_query_string);
$data = $q->do_query($node, $query_string);
if ($data[0] == 1)
    print $data[1];
?>
