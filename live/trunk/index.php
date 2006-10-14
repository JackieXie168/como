<?php
    if (!file_exists("comolive.conf")) {
        require_once "include/framing.php";
        require_once "include/helper-messages.php";
        $header = simple_header(NULL);
        $footer = simple_footer();
        $mesg = "Thanks for downloading CoMoLive!<br>";
        $mesg .= "Lets get started!<br><br>";
        $mesg .= "Click <a href=config/>here</a> to setup CoMoLive!";
        $generic_message = $mesg;
        include ("html/generic_message.html");
        exit;
        /** 
         *  Not using the generic_messgage function becuase of the 
         *  path to the html directory.  May change this if a sym
         *  link to the include dir is included in the site dirs
         */
    } else {
        header ("Location: public/index.php");
    }
?>
