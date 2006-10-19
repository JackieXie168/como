<!--  $Id$  -->
<?php
/**
 *  Function to create the site.  Create all links to necessary files  
 *  manage_site (global var, name of site, CREATE|DELETE);
 */
function manage_site ($G, $sitename, $action) 
{
    $dname = $G['ABSROOT'] . "/" . $sitename;
    if ($action == "CREATE") {
        $srcname = $G['ABSROOT'] . "/php";
        if ($sitename != "admin") {
            /*  Create the site directory  */
            mkdir ($dname, 0755);
            /*  Create the sym links  */
            $symname[0] = "dashboard.php";
            $symname[1] = "generic_query.php";
            $symname[2] = "index.php";
            $symname[3] = "loadcontent.php";
            $symname[4] = "mainstage.php";
            $symname[5] = "sysinfo.php";
            for ($i = 0; $i < count($symname); $i++) {
                $orig = $srcname . "/" . $symname[$i];
                $dest = $dname . "/" . $symname[$i];
                symlink($orig, $dest);
            }
            /*  Create the results and db directory  */
            mkdir("$dname/{$G['RESULTS']}", 0755);
            mkdir("$dname/{$G['NODEDB']}", 0755);
        } else {
            /*  Create the links to db and results  */
            $orig = $G['ABSROOT'] . "/db";
            $dest = $G['ABSROOT'] . "/admin/db";
print "orig $orig and dest $dest";
            symlink($orig, $dest);
            $orig = $G['ABSROOT'] . "/results";
            $dest = $G['ABSROOT'] . "/admin/results";
            symlink($orig, $dest);
            /*  Write out .htpasswd and .htaccess files  */
            $htpwd = $G['ABSROOT'] . "/admin";
            $htaccess = "AuthName \"CoMoLive! Admin\"\n" . 
                        "AuthType Basic\n" . 
                        "AuthUserFile $htpwd/.htpasswd\n" . 
                        "Require valid-user\n";
            system ("htpasswd -b -c $htpwd/.htpasswd admin {$G['PASSWORD']}");
            file_put_contents("$htpwd/.htaccess", $htaccess);
        }
    }
    /*  Cleanup site dir  */
    /*  Not finished  */
    if (($action == "DELETE") && ($sitename != "public")){
        $symname[0] = "dashboard.php";
        $symname[1] = "generic_query.php";
        $symname[2] = "index.php";
        $symname[3] = "loadcontent.php";
        $symname[4] = "mainstage.php";
        $symname[5] = "sysinfo.php";
        for ($i = 0; $i < count($symname); $i++) {
            $orig = $srcname . "/" . $symname[$i];
            unlink($orig);
        }
        $dadest = $G['ABSROOT'] . "/OLDGROUPS";
        if (!(file_exists($dadest))) {
            mkdir ($dadest, 0775);
        }
        $destfile = $dadest . "/" . $sitename;
        rename ($dname, $destfile);
    }
}

function check_writable ($dir)
{
    /*  This will check to make sure all directories are there and
     *  writeable.
     */
    if (!(file_exists($dir)) || (!(is_writable($dir)))) {
        return 0;
    } else {
        return 1;
    }

}
?>
