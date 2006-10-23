<?php
    /*  $Id$  */
    require_once ("../comolive.conf");
    include_once ("../include/framing.php"); 
    include_once ("../include/helper-messages.php"); 
    include_once ("../include/helper-filesystem.php"); 
    include_once ("../class/node.class.php");
   
    $G = init_global();

    $header = do_header(NULL, $G);
    $footer = do_footer(NULL);

    $ALLOWCUSTOMIZE = $G['ALLOWCUSTOMIZE'];
    $NODEDB = $G['NODEDB'];
    $ABSROOT = $G['ABSROOT'];

    /* Don't allow entrace without customization priviledge  */
    if (!($ALLOWCUSTOMIZE)) {
        header("Location: index.php");
        exit;
    }
    $method = "addnode";
    if (isset($_GET['method']))
        $method = $_GET['method'];

    /*  sitename is passed from the previous page when adding a site  */
    if (isset($_GET['sitename']) && $_GET['sitename'] != "")
        $sitename = $_GET['sitename'];

    /* get the node hostname and port number */
    if (!isset($_GET['comonode'])) {
        $mes = "This file requires the comonode=host:port arg passed to it";
        generic_message($mes);
    }
    $comonode = $_GET['comonode'];

    $groupfname = $NODEDB . "/groups.lst";
    $nodefname = $NODEDB . "/nodelist.lst";


    switch ($method) { 
    case "Submit": 
        if (isset($_GET['nodename']))
            $nodename= trim($_GET['nodename']);
        if (isset($_GET['nodeplace']))
            $nodeplace = trim($_GET['nodeplace']);
        if (isset($_GET['speed']))
            $speed = trim($_GET['speed']);
        if (isset($_GET['comment']))
            $comment = trim($_GET['comment']);
        /*  Sites is an array of sites submitted  */
        if (isset($_GET['sites']))
            $sites = $_GET['sites'];
        $numsites = count($sites);

        /*  Make sure the public hasn't been deleted  */
        if (!file_exists("$ABSROOT/public")) {
            manage_site($G, "public", "CREATE");
        }

        /*  Write the column header info  */
        $tofile = "Name;;CoMo Name:Port;;Location;;Interface;;Comments;;Groups;;Tags;;\n";

        /*  Build site array  */
        $siteval = "";
        foreach ($sites as $value) {
            $siteval .= $value . "*;*";
        }

        /*  Is this node in the file already?  */
        $alreadythere = 0;
        $val = file($nodefname); 
        for ($i = 1; $i < count($val); $i++) {
            /*  If it is there, just modify group info  */
            if (strstr($val[$i], $comonode)) {
                $contents = explode(";;", $val[$i]);
                $contents[5] = $siteval;
                $val[$i] = implode(";;", $contents);
                $tofile .= $val[$i];
                $alreadythere = 1;
            } else {
                $tofile .= $val[$i];
 
            }
        }
        /*  Node does not exist, write it  */
        if (!$alreadythere) {
            /*  Write the node data to the file  */
            $tofile .= $nodename . ";;" ;
            $tofile .= $comonode . ";;" ;
            $tofile .= $nodeplace . ";;" ;
            $tofile .= $speed . ";;" ;
            $tofile .= $comment . ";;" ;
            $tofile .= $siteval . ";;\n" ;
        }

        file_put_contents($nodefname, $tofile);

        header("Location: index.php");
        break; 

    case "Add Group": 
        /**
         * Get the contents of the group file 
         */         
        if (isset($sitename)) {
            $all_groups = file ($groupfname);
            /*  Make sure this site doesn't already exist  */
            if (!(in_array($sitename . "\n", $all_groups))) {
                $towrite = "$sitename\n";
                file_put_contents($groupfname, $towrite, FILE_APPEND) ||
                    generic_message("Cannot write to file '$groupfname', " .
                                    "please check permissions");
                manage_site($G, $sitename, "CREATE");
            }
        }
        /**
         *  If we add a group, we need to go through the addnode
         *  case.  I am commenting out the break and reassigning $method
         *  And so let it be commentted :)
         */
        $method = "addnode";
        /* break; */

    case "addnode": 

        /*  query the CoMo node  */
        $node = new Node($comonode,$G);
        if ($node->status == 0) { 
            include ("../html/node_failure.html");
            exit; 
        }

        /*  create the group file */
        if (!file_exists($groupfname)) {
            touch($groupfname);
        }

        if (file_exists($groupfname)) {
            $val = "public";
            $all_groups = file($groupfname);
            /*  Put public at beginning of the array  */
            array_unshift($all_groups, $val);
        } else {
            $all_groups[0] = "public";
        }

        /**  
         *  Check if the node exists in the nodefile 
         *  This is just to get the list of groups this node belongs 
         *  to so we can check boxes when we are modifying
         */
        $memberlist[0] = "public*;*";
        if (file_exists($nodefname)) {
            $val = file($nodefname);
            for ($i = 1; $i < count($val); $i++) {
                $desc = split(';;', $val[$i]);
                if ($comonode == $desc[1]) {
                    $memberlist = explode("*;*", $desc[5]);
                }
            }
        } 
        break;
    }
    include ("nodeview.html");

function list_dir ($handle, $NODEDB) 
{
    $x = 0;
    while (false !== ($filez = readdir($handle))) {
       if ($filez!= "." && $filez!= ".." && ereg (".*\.lst$", $filez)) {
           if (file_exists("$NODEDB/$filez")) {
               $desc = file ("$NODEDB/$filez");
               $all_groups[$x]['filename'] = $filez;
               $all_groups[$x]['desc'] = $desc[0];
               $x++;
           }
       }
    }
    if (isset($all_groups)) {
        return ($all_groups);
    }
}
?>

