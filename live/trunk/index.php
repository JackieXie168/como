<?php
    if (!file_exists("comolive.conf")) {
        header ("Location: admin/index.php");
    } else {
        header ("Location: public/index.php");
    }
?>
