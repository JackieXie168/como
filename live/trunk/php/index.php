<?php
    /*  $Id$  */
    require("../include/compat.php");
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
	$mesg = "Please click <a href=../config/>here</a> to create a ";
        $mesg .= "comolive.conf file<br>"; 
        $generic_message = $mesg;
        include("../html/generic_message.html");
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

    $header = do_header(NULL, $G);
    $footer = do_footer(NULL);

    include ("../html/nodelist.html");
?>
