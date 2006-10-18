<?
     /*  $Id$  */
    require_once ("../comolive.conf");
    require_once ("../class/node.class.php");
    require_once ("../include/framing.php"); 
    require_once ("../include/helper-filesystem.php"); 

    $G = init_global();
    $ALLOWCUSTOMIZE = $G['ALLOWCUSTOMIZE'];
    $NODEDB = $G['NODEDB'];
    $ABSROOT = $G['ABSROOT'];

    $header = do_header(NULL, 1);
    $footer = do_footer(NULL);

    /*  Don't allow entrace without customization priviledge  */
    if (!$ALLOWCUSTOMIZE) {
        header("Location: index.php");
        exit;
    }
    /*  get the node hostname and port number */
    $comonode = "";
    if (isset($_GET['comonode']))
	$comonode = $_GET['comonode'];

    $group = "";
    if (isset ($_GET['group']))
        $group = trim($_GET['group']);

#    $nodefile = "$group";
    $groupfname = $NODEDB . "/groups.lst";
    $nodefname = $NODEDB . "/nodelist.lst";


    $action = "add";
    if (isset ($_GET['action']))
        $action = $_GET['action'];

    /*  Delete a entry in the config file matching comonode  */
    if ($action == "delete") {
        $datafile = file ($nodefname);
        $tofile = "";
        /*  Loop thru the datafile and delete the group membership  */
        for ($i = 0; $i < count($datafile); $i++){
            if ($i == 0) {
    	        $tofile = $tofile . $datafile[$i];
            } else {
		$val = explode (";;", $datafile[$i]);

                /*  If match, delete the group membership  */
		if ($comonode == $val[1]){
                    /*  group membership in 5th element  */
                    $val = explode ("*;*", $val[5]);
                    $valcount = count($val);
                    print "count is $valcount<br>";
                    /*  if there are no more groups left, don't write the line*/
                    if (count($val) > 2) {
                        $findit = $group . "\*;\*";
                        $newval = ereg_replace($findit, "", $datafile[$i]);
                        $tofile = $tofile . $newval;
                    }
		} else {
		    $tofile = $tofile . $datafile[$i];
                }
            }
        }
        file_put_contents($nodefname, $tofile);
	header("Location: index.php");
    }
    if ($action == "groupdel"){
        $datafile = file ($groupfname);
        $tofile = "";
        for ($i = 0; $i < count($datafile); $i++){
            if (trim($datafile[$i]) != $group) {
                $tofile .= $datafile[$i];
            }

        }
        /*  Write out new file  */
        file_put_contents($groupfname, $tofile);
        /*  Go through the node list and remove the group entry  */
        $datafile = file ($nodefname);
        $tofile = "";
        /*  Loop thru the datafile and delete the group membership  */
        for ($i = 0; $i < count($datafile); $i++){
            if ($i == 0) {
    	        $tofile = $tofile . $datafile[$i];
            } else {
		$val = explode (";;", $datafile[$i]);
                /*  group membership in 5th element  */
                $val = explode ("*;*", $val[5]);
                /*  if there are no more groups left, don't write the line*/
                if (count($val) > 2) {
                    $findit = $group . "\*;\*";
                    $newval = ereg_replace($findit, "", $datafile[$i]);
                    $tofile = $tofile . $newval;
                }
            }
        }
    }
    file_put_contents($nodefname, $tofile);

    /*  Move the group directory to OLDGROUP  */
    manage_site($G, $group, "DELETE");

    header("Location: index.php");
    ?>
