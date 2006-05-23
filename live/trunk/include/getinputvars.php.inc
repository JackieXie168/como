<!--  $Id$ -->
<!--  The following variables are set with this file
      . modules
      . filter
      . stime and etime (require node to be instantiated)
      . format
      . ip
      . http_query_string
-->
<?
/*  getinputvars.php.inc
 *
 */
#
# GET input variables
#
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

    if (isset($_GET['etime']) && ($_GET['etime'] != "")){
	$input_vars['etime'] = $_GET['etime'];
	if (isset($node)){
	    $node->SetEndtime($input_vars['etime']);
	}
    } else
	$input_vars['etime'] = $node->etime;
    if(isset($_GET['stime']) && ($_GET['stime'] != "")){
	$input_vars['stime'] = $_GET['stime'];
	if (isset($node)){
	    $input_vars['stime'] = $node->CheckFirstPacket($input_vars['stime'],$input_vars['module']);
	    $node->SetStarttime($input_vars['stime']);
	}
    } else
	$input_vars['stime'] = $node->stime;

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
