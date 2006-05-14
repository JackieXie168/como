<?php
if (isset ($_GET['sub'])) 
    $sub = $_GET['sub'];
else
    $sub = "none";

if (isset ($_GET['webroot'])) 
    $webroot = $_GET['webroot'];

?>
<div class=secmenubar>
    <ul>
<?
    if ($sub == "system") {
	print "    <li><a href=$webroot>CoMo System List</a></li>";
#	print "    <li>DDI(Distributed Data Inference)</li>";
    }
    if ($sub == "application") {
#	print "    <li>Blinc View </li>";
#	print "    <li>DDI(Distributed Data Inference)</li>";
    }
    if ($sub == "help") {
	print "    <li><a href=http://como.intel-research.net/people.php>";
        print "    People</a></li>";
	print "    <li><a href=http://como.intel-research.net/publications.php>";
        print "    Publications</a></li>";
	print "    <li><a href=http://como.intel-research.net/software.php>";
        print "    Software</a></li>";
	print "    <li><a href=http://como.intel-research.net>";
        print "    About CoMo</a></li>";
    }
?>

    </ul>
</div>
