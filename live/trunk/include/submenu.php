<!--  $Id$  -->
<?php 

$sub = "none";
if (isset($_GET['sub'])) 
    $sub = $_GET['sub'];

if (isset($_GET['webroot'])) 
    $webroot = $_GET['webroot'];

if (isset($_GET['comonode'])) 
    $comonode = $_GET['comonode'];
?>

<div class=secmenubar>
    <ul>
    <?php if ($sub == "view") { ?>
    <li>
        <a href=<?php echo $webroot?>>
        &nbsp;&nbsp;&nbsp;List&nbsp;&nbsp;&nbsp;</a>
    </li>
    <li>
        <a href=worldview.php>
        &nbsp;&nbsp;&nbsp;Map&nbsp;&nbsp;&nbsp;</a>
    </li>
    <?php
        if (isset ($_GET['customize'])) {
            $custom_link = "<a href=# onClick=\"return customize=window.open('$webroot/admin/customize.php?comonode=$comonode','customize','width=700,height=450,status=no,scrollbars=yes'); return false;\">&nbsp;&nbsp;&nbsp;Customize&nbsp;&nbsp;&nbsp;</a>";
        } else {
            $custom_link = "&nbsp;&nbsp;&nbsp;Customize&nbsp;&nbsp;&nbsp;";
        }
        echo $custom_link;

    } else if ($sub == "system") { 
    ?>
    <li>
        <a href=sysinfo.php/?comonode=<?php echo $comonode?> target=new> 
        &nbsp;&nbsp;&nbsp;Properties&nbsp;&nbsp;&nbsp;</a>
    </li>
    <li>
    <?php 
    }
    ?>
    </li>
    <?php  
    if ($sub == "help") { ?>
    <li>
        <a href=http://como.intel-research.net>
        &nbsp;&nbsp;&nbsp;About CoMo&nbsp;&nbsp;&nbsp;</a>
    </li>
    <?php } ?>
    <?php  
    if ($sub == "setup") { ?>
    <li>
        <a href=../admin>
        &nbsp;&nbsp;&nbsp;Add Nodes&nbsp;&nbsp;&nbsp;</a>
    </li>
    <?php } ?>
    </ul>
</div>
