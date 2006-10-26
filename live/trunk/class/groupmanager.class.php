<?php
/*
 * $Id$
 */

class GroupManager {
    var $groups_file;
    var $passwords_file;
    var $groups;
    var $absroot;
    var $nodedb;
    var $results;

    function GroupManager($G) {
        $this->absroot = $G['ABSROOT'];
        $this->nodedb = $G['NODEDB'];
        $this->results = $G['RESULTS'];
        $this->groups_file = $G['ABSROOT'].'/'.$G['NODEDB'].'/'.'groups';
        $this->passwords_file = $G['ABSROOT'].'/'.$G['NODEDB'].'/'.'passwords';

        if (!file_exists($this->groups_file)) {
            $this->groups = array();
            $this->createGroupDir('admin');
            $this->addGroup('public');
            $this->save();
            $this->setPassword('admin', 'admin');
        } else {
            $contents = file($this->groups_file);
            foreach ($contents as $line) {
                $line = rtrim($line);

                // split by ':' to get the group name
                $tmp = split(':', $line);
                $name = $tmp[0];

                // rejoin, then split by ',' to get the node list
                unset($tmp[0]);
                $nodes_str = implode(':', $tmp);
                if ($nodes_str == '') {
                    $this->groups[$name] = array();
                } else {
                    $nodes = split(',', $nodes_str);
                    $this->groups[$name] = $nodes;
                }
            }
        }
    }

    function haveGroup($name)
    {
        return array_key_exists($name, $this->groups);
    }

    function addGroup($name)
    {
        if ($this->haveGroup($name))
            return;

        $this->createGroupDir($name);

        $this->groups[$name] = array();
        $this->save();
    }

    function removeGroup($name)
    {
        unset($this->groups[$name]);

        $src = $this->absroot.'/'.$name;
        $dst = $this->absroot.'/OLDGROUPS/'.$name;

        if (file_exists($dst)) { # if dest exists, append a number
            $i = 2;
            while (file_exists($dst."-$i"))
                $i++;
            $dst .= "-$i";
        }

        rename($src, $dst) || $this->reportFailure($src.' or '.$dst);
        $this->save();
    }

    function addNode($group, $node)
    {
        if (! $this->haveGroup($group)) // create group if does not exist
            $this->addGroup($group);
        array_push($this->groups[$group], $node);
        $this->save();
    }

    function removeNode($group, $node)
    {
        if (! $this->haveGroup($group))
            return;

        $array = $this->groups[$group];
        foreach ($array as $idx => $value) {
            if ($value != $node)
                continue;
            unset($array[$idx]);
            break;
        }
        $this->groups[$group] = $array;
        $this->save();
    }

    function getNodes($group)
    {
        return $this->groups[$group];
    }

    function getGroups()
    {
        return array_keys($this->groups);
    }

    /*
     * save info to groups file
     */
    function save()
    {
        $str = '';
        foreach ($this->groups as $group => $nodes) {
            $str .= "$group:";
            $prepend = '';
            foreach ($nodes as $node) {
                $str .= ($prepend . $node);
                $prepend = ',';
            }
            $str .= "\n";
        }
        file_put_contents($this->groups_file, $str);
    }

    /*
     * deploy all the info to the users' environment
     */
    function deploy()
    {
        foreach ($this->groups as $group => $x)
            $this->deployGroup($group);
        $this->deployAdminGroup();
    }

    function deployGroup($group)
    {
        $filename = $this->absroot.'/'.$group.'/'.$this->nodedb.'/nodes.lst';
        $str = '';
        foreach ($this->groups[$group] as $node)
            $str .= "$node\n";

        $ret = file_put_contents($filename, $str);
        if ($ret === false) { /* use === (three ='s) to make sure that 0
                               * is not interpreted as false.
                               */
            print "ret = $ret";
            $this->reportFailure($filename);
        }

        $filename = $this->absroot.'/'.$group.'/'.$this->nodedb.'/mygroup';
        $ret = file_put_contents($filename, $group);
        if ($ret === false)
            $this->reportFailure($filename);
    }

    /*
     * the admin group gets all the data
     */
    function deployAdminGroup()
    {
        $filename = $this->absroot.'/admin/'.$this->nodedb.'/nodes.lst';
        $str = '';
        foreach ($this->groups as $group => $nodes)
            foreach ($nodes as $node)
                $str .= "$node\n";

        $ret = file_put_contents($filename, $str);
        if ($ret === false)
            $this->reportFailure($filename);

        $filename = $this->absroot.'/admin/'.$this->nodedb.'/mygroup';
        $ret = file_put_contents($filename, 'admin');
        if ($ret === false)
            $this->reportFailure($filename);
    }

    function reportFailure($file)
    {
        print "WARNING: failed to write to '$file', check permissions!<br>\n";
    }

    function my_mkdir($dir) {
        if (!file_exists($dir))
            mkdir($dir) || $this->reportFailure($dir);
    }

    function my_symlink($a, $b) {
        if (!file_exists($b))
            return symlink($a, $b);
    }

    function createGroupDir($user)
    {
        $dir = $this->absroot.'/'.$user.'/';

        $this->my_mkdir($dir);
        $this->my_mkdir($dir.'/'.$this->nodedb);
        $this->my_mkdir($dir.'/'.$this->results);
        $this->my_mkdir($dir.'/java');

        $links = array("dashboard.php", "generic_query.php", "index.php",
            "loadcontent.php", "mainstage.php", "sysinfo.php", "search.php");

        foreach ($links as $l)
            $this->my_symlink("../php/$l", $dir . $l);

        $links = array("getdata.php", "pack.jar", "prefuse.jar");

        foreach ($links as $l)
            $this->my_symlink("../../java/$l", $dir . "java/$l");

        if ($user == 'admin')
            $this->my_symlink('../'.$this->nodedb, $dir.$this->nodedb);

        // create .htaccess file
        if ($user != 'public') {
            $contents = <<<EOF
AuthName "CoMoLive! - $user" 
AuthType Basic 
AuthUserFile $this->passwords_file
AuthGroupFile /dev/null 
require valid-user
EOF;
            file_put_contents($dir.'.htaccess', $contents); # || die "adsf";
        }
    }

    function setPassword($user, $password)
    {
        $user = escapeshellcmd($user);
        $password = escapeshellcmd($password);
        $file = escapeshellcmd($this->passwords_file);
        $flags = "";
        if (! file_exists($file))
            $flags = '-c';
        $command = "/usr/sbin/htpasswd2 $flags -b $file $user $password";
        shell_exec($command);
    }
}

?>
