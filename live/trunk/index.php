<?php
    if (!file_exists("comolive.conf")) {
        header ("Location: php/index.php");
    } else {
        header ("Location: groups/public/index.php");
    }
?>
