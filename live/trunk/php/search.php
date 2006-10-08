<?php
    $filter = isset($_POST['filter'])? "filter={$_POST['filter']}" : ""; 
    header("Location: generic_query.php?{$_SERVER['QUERY_STRING']}&$filter"); 
?>

