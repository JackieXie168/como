<?php

    if (!file_exists("comolive.conf")) {
        require_once "include/framing.php";
        $header = simple_header(NULL);
        $footer = simple_footer();
        $mesg = "Thanks for downloading CoMoLive!<br>";
        $mesg = $mesg . "Lets get started!<br><br>";
        $mesg = $mesg . "Click <a href=config/>here</a> to setup CoMoLive!";
        $generic_message = $mesg;
        include("html/generic_message.html");
        exit;
    } else {
        header ("Location: public/index.php");
    }


?>
