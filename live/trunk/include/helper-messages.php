<!--  $Id:  -->
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
?>
