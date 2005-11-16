<!-- $Id$ -->

<!-- 
    This is the drop down menu to access the various parts of the
    CoMolive! website. 
--> 

<script type="text/javascript">
<!--
function showmenu(name, id) {
    clearmenu(name);
    var d = document.getElementById(name + id);
    if (d)
        d.style.display='block';
}

function clearmenu(name) {
  for (var i = 1; i <= 10; i++) {
    if (document.getElementById('smenu'+i)) {
      document.getElementById('smenu'+i).style.display='none';
    }
  }
}

//-->
</script>

<div id=menu>
  <dl>
    <dt onmouseover="javascript:showmenu('smenu', 1);">
      <a href="#">Systems</a>
    </dt>
    <dd id="smenu1" onmouseover="javascript:showmenu('smenu', 1);">
      <ul>
	<li><a href="index.php">Map</a></li>
	<li><a href="list.php?area=all">List nodes</a></li>
	<li><a class=inactive href="#">Search nodes</a></li>
      </ul>
    </dd>
  </dl>
  <dl>
    <dt onmouseover="javascript:showmenu('smenu',2);">
      Queries
    </dt>
    <dd id="smenu2">
      <ul>
	<li><a class=inactive href="query/broadcast.php">Broadcast query</a></li>
	<li><a class=inactive href="#">Upload source</a></li>
	<li><a class=inactive href="#">Ad-hoc query</a></li>
	<li><a class=inactive href="#">Query planning</a></li>
      </ul>
    </dd>
  </dl>


<?php
  if ($level == "system") {
?>
  <dl>
    <dt onmouseover="javascript:showmenu('smenu',3);">
      Modules
    </dt>
    <dd class=modules id="smenu3" onmouseover="javascript:showmenu('smenu',3);">
      <ul>
	<li>
           <?php
	   print "<a href=system.php?";
	   print "node=$host&module=counter&stime=$stime&etime=$etime>";
	   print "Traffic Load</a></li>";
           ?>
	<li>
	   <?php
	   print "<a href=system.php?"; 
	   print "node=$host&module=utilization&stime=$stime&etime=$etime>";
	   print "Load High Watermark</a></li>";
           ?>
	<li>
	   <?php
	   print "<a href=system.php?"; 
	   print "node=$host&module=protocol&filter=ip";
	   print "&stime=$stime&etime=$etime>";
	   print "Protocol Breakdown</a></li>";
           ?>
	<li>
	   <?php
	   print "<a href=\"system.php?"; 
	   print "node=$host&module=application&filter=tcp";
	   print "&stime=$stime&etime=$etime\">";
	   print "Application Breakdown</a></li>";
           ?>
	<li>
	   <?php
	   $topend = $stime + 3600; 
	   print "<a target=new href=\"textquery.php?"; 
	   print "node=$host&module=topdest&filter=ip&format=pretty";
	   print "&stime=$stime&etime=$topend\">";
	   print "Top destinations</a></li>";
           ?>
<!--
        <li>
           <?php /*
           print "<a href=\"system.php?";
           print "node=$host&module=snort&filter=ip";
           print "&stime=$stime&etime=$etime\">";
           print "Snort module</a></li>"; */
           ?>
-->
      </ul>
    </dd>
  </dl>
<?php
  } 
?>
  <dl>
    <dt onmouseover="javascript:clearmenu('smenu')">
    &nbsp;
    </dt>
  </dl>
</div>

