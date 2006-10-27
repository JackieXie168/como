<?php
    /*  $Id$  */
    /* 
     * this is the entry page to the CoMolive! site. show the banner
     * and add the usual html header stuff. 
     */
    include("../include/framing.php");
    $header = simple_header("../");
    $footer = simple_footer();
    /* 
     * look for comolive.conf. it is a required file but cannot use
     * require_once directly because it causes a warning on the screen 
     * and nothing else. First we check if the file exists. If not we 
     * write a message on the screen and terminate. 
     * 
     * XXX note that this check is only required in index.php given 
     *     that we can safely assume that is the file people will 
     *     access first. A better option would be to define default 
     *     configuration values somewhere else and then use comolive.conf
     *     just to change the default values.
     * 
     */ 

    if (!file_exists("../comolive.conf")) {
        require_once "../include/framing.php";
        require_once "../include/helper-messages.php";
        $header = simple_header('..');
        $footer = simple_footer();
        $mesg = "Thanks for downloading CoMoLive!<br>";
        $mesg .= "Let's get started!<br><br>";
        $mesg .= "Click <a href=../config/>here</a> to setup CoMoLive!";
        $generic_message = $mesg;
        include ("../html/generic_message.html");
        exit;
    }

    require_once "../comolive.conf";
    require_once "../class/nodedb.class.php";

    if (!(isset ($G)))
	$G = init_global();

    $db = new NodeDB($G);
    $nodes = $db->getNodeList();

    /* 
     * get all the groups that have been created  
     * They should be located in the db directory and 
     * have a lst extension
     */
  
    $ALLOWCUSTOMIZE = $G['ALLOWCUSTOMIZE'];
    $isAdmin = 0;
    if ($db->getGroup() == 'admin') {
        $isAdmin = 1;
        require_once "../class/groupmanager.class.php";
        /*
         * we are admin. need to render not only the nodes
         * but also the groups they belong to, so we do
         * this differently.
         */
        $m = new GroupManager($G);
        $groups = $m->getGroups();
        $nodes = array();
        $groups = array();
        $emptygroups = array();
        foreach ($m->getGroups() as $g) {
            $empty = 1;
            foreach ($m->getNodes($g) as $n) {
                $nodes[] = $n;
                $groups[] = $g;
                $empty = 0;
            }

            if ($empty)
                $emptygroups[] = $g;
        }
    }

    /*
     * If we are doing a search we need to prepare the list
     * of what nodes actually matched the user's query.
     */
    $filter = '';
    $node_filter = array();
    if (isset($_GET['filter'])) {
        $filter = urlencode($_GET['filter']);
        $time = 3600 * 5;
        $query = "traffic?time=-${time}s:0&wait=no&filter=$filter&source=tm&format=plain";
        foreach ($nodes as $node) {
            if (array_key_exists($node, $node_filter))
                continue; // done, can happen when isAdmin and a node
                          // belongs to more that one group
            $q = "http://$node/" . $query;
            $output = file($q);
            $output = $output[0];
            #print "$query<br>\n";
            #print " ---> $output<br>\n";
            $node_filter[$node] = count($output) == 0 ? 0 : 1;
        }
    } else {
        foreach ($nodes as $node)
            $node_filter[$node]=1;
    }

    $header = do_header(NULL, $G);
    $footer = do_footer(NULL);

    include ("../html/nodelist.html");
?>
