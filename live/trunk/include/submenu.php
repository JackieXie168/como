<?php 

if (isset ($_GET['sub'])) 
    $sub = $_GET['sub'];
else
    $sub = "none";

if (isset ($_GET['webroot'])) 
    $webroot = $_GET['webroot'];

if (isset ($_GET['comonode'])) 
    $comonode = $_GET['comonode'];

?>

<div class=secmenubar>
  <ul>
<? if ($sub == "view") { ?>
    <li>
      <a href=<?=$webroot?>>
      &nbsp;&nbsp;&nbsp;List&nbsp;&nbsp;&nbsp;</a>
    </li>
    <li>
      <a href=<?=$webroot?>>
      &nbsp;&nbsp;&nbsp;Map&nbsp;&nbsp;&nbsp;</a>
    </li>
<? } else if ($sub == "system") { ?>
    <li>
      <a href=$webroot>
      &nbsp;&nbsp;&nbsp;Properties&nbsp;&nbsp;&nbsp;</a>
    </li>
    <li>
<?php
    if (isset ($_GET['customize'])) 
	$custom_link = "<a href=# onClick=\"return customize=window.open('customize.php?comonode=$comonode','customize','width=700,height=450,status=no,scrollbars=yes'); return false;\">&nbsp;&nbsp;&nbsp;Customize&nbsp;&nbsp;&nbsp;</a>";
    else
	$custom_link = "&nbsp;&nbsp;&nbsp;Customize&nbsp;&nbsp;&nbsp;";
?>
      <?=$custom_link?>
    </li>
<? } if ($sub == "help") { ?>
    <li>
      <a href=http://como.intel-research.net>
      &nbsp;&nbsp;&nbsp;About CoMo&nbsp;&nbsp;&nbsp;</a>
    </li>
<? } ?>
  </ul>
</div>
