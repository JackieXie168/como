<?php
/*  $Id:$  */

    $patterns = array ("/\/groups.*/", "/\/admin.*/", "/\/config.*/" );
    $ABSROOT = preg_replace($patterns, '', $_SERVER['SCRIPT_FILENAME']);

require_once ("$ABSROOT/comolive.conf");
$G = init_global();

require_once ("class/groupmanager.class.php");

function haveparam($name) {
    return array_key_exists($name, $_GET);
}
function getparam($name, $allow_failure = 0) {
    if (! $allow_failure && ! array_key_exists($name, $_GET))
        exit; /* missing parameter */
    return $_GET[$name];
}

$m = new GroupManager($G);
$action = getparam('action', 1);

if ($action == 'remove_node') {
    $node = getparam('node');
    $group = getparam('group');
    $m->removeNode($group, $node);
    $m->deploy();
}
else if ($action == 'remove_group') {
    $group = getparam('group');
    $m->removeGroup($group);
    $m->deploy();
}
else if ($action == 'add_group') {
    $group = getparam('group');
    $password = getparam('password');
    if ($group == 'admin') //admin is a special group, we dont let it be added
        $group = 'admingroup';
    $m->addGroup($group);
    $m->setPassword($group, $password);
    $m->deploy();
}
else if ($action == 'add_node') {
    $node = getparam('node');
    if (haveparam('groups')) {
        $groups = getparam('groups');
        foreach ($groups as $g)
            $m->addNode($g, $node);
        $m->deploy();
    } else {
        require_once ("include/framing.php");
        $header = do_header(NULL, $G);
        $footer = do_footer(NULL);
        $groups = $m->getGroups();
        include ("nodeview.html");
        exit;
    }
}
else {
    print "unknown action $action\n";
    exit;
}
header('location:index.php');

?>
