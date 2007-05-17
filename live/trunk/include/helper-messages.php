<!--  $Id$  -->
<?php
function generic_message ($mesg) 
{
    require_once("framing.php");
    $header = simple_header("../");
    $footer = simple_footer();
    $generic_message = $mesg;
    include("../html/generic_message.html");
    exit;
    
}

function ERROR_DIRNOTWRITABLE ($dir) 
{
    $m = "Please make sure the $dir directory ".
         "exists and is writeable <br>" .
         "by the web server<br><br>" .
         "<pre>" .
         "mkdir $dir;<br>" .
         "chown ".rtrim(`id -nu`)." $dir; <br></pre>";
        $val = $m;
    return $val;

}

?>
