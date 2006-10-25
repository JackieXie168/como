<?php
/*
 * $Id$
 */

/*
 * Can read the node database that the GroupManager class
 * generates.
 */
class NodeDB {
    var $file;
    var $group;

    function NodeDB($G)
    {
        $this->file = $G['NODEDB'].'/nodes.lst';

        $tmp = file($G['NODEDB'].'/mygroup');
        $this->group = rtrim($tmp[0]);
    }

    function getGroup()
    {
        return $this->group;
    }

    function getNodeList()
    {
        return array_map('rtrim', file($this->file));
    }

    function hasNode($node)
    {
        $nodes = $this->getNodeList();
        foreach ($nodes as $n)
            if ($n == $node)
                return true;

        return false;
    }
}
?>
