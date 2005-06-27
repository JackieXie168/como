<!-- $Id$ --> 

<html>

<?php $nodename = NULL; include("include/header.php"); ?>
<?php $level = "top"; include("include/menulist.php"); ?>

<div id=content> 
  <div class=graph>
    <!-- put the map of your choice here -->
    <img src=images/worldmap.jpg usemap="#worldmap">
  
    <map id="worldmap" name="worldmap">
      <area shape=rect coords="266,53,345,150" 
            href="list.php?area=europe" 
            alt="Europe">
      <area shape=rect coords="18,0,190,195" 
            href="list.php?area=north_america" 
            alt="North America">
<!--
      <area shape=rect coords="150,195,230,320" 
            href="list.php?area=south_america"
            alt="South America">
      <area shape=rect coords="250,150,370,280" 
            href="list.php?area=africa" 
            alt="Africa">
      <area shape=rect coords="345,0,590,220" 
            href="list.php?area=asia"
            alt="Asia">
      <area shape=rect coords="460,220,570,310" 
            href="list.php?area=oceania"
            alt="Oceania">
  -->
    </map>
  </div>

  <div class=sysinfo onmouseover="javascript:clearmenu('smenu')">

    <!-- some static information... -->

    <div class=title> CoMo Status</div>
    Monitored Links: ??<br>
    Data Sources: <br>
    &nbsp; &nbsp; &nbsp; x Gigabit Ethernet<br>
    &nbsp; &nbsp; &nbsp; y Sampled NetFlow<br>
    Link Speeds: <br> 
    &nbsp; &nbsp; &nbsp; x x 1 Gbps<br>
    &nbsp; &nbsp; &nbsp; y x 2.4 Gbps<br>

    <br><br><br>
    Select node by IP address
    <form action=system.php method=get>
      <input type=text name=node size=21>
      <input type=image src=images/go.jpg>
    </form>
  </div>

</div>

<? include("include/footer.php"); ?>

</html>


