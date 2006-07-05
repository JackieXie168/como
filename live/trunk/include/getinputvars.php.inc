<?php
/*  $Id$  */

/*  getinputvars.php.inc
 *
 */
function init_env ($node) {
    $input_vars = array();
    if (isset($_GET['module']) && ($_GET['module'] != ""))
	$input_vars['module'] = $_GET['module'];
    else
	$input_vars['module'] = "traffic";

    if (isset($_GET['filter']) && ($_GET['filter'] != ""))
	$input_vars['filter'] = $_GET['filter'];
    else
	$input_vars['filter'] = "all";

    if (isset($_GET['end']) && ($_GET['end'] != "")){
	$input_vars['end'] = $_GET['end'];
	if (isset($node)){
	    $node->SetEndtime($input_vars['end']);
	}
    } else
	$input_vars['end'] = $node->end;
    if(isset($_GET['start']) && ($_GET['start'] != "")){
	$input_vars['start'] = $_GET['start'];
	if (isset($node)){
	    $input_vars['start'] = $node->CheckFirstPacket($input_vars['start'],$input_vars['module']);
	    $node->SetStarttime($input_vars['start']);
	}
    } else
	$input_vars['start'] = $node->start;

    if(isset($_GET['format']) && ($_GET['format'] != ""))
	$input_vars['format'] = $_GET['format'];
    else
	$input_vars['format'] = "gnuplot";

    if(isset($_GET['ip']) && ($_GET['ip'] != ""))
	$input_vars['ip'] = $_GET['ip'];

    $input_vars['http_query_string'] = $_SERVER['QUERY_STRING'];

    return ($input_vars);
}

?>
