<!--  $Id$  -->

<?php
    /* 
     * this is the entry page to the CoMolive! site. show the banner
     * and add the usual html header stuff. 
     */
    $includebanner=1;
    include("include/header.php.inc");
?>

<body>
<table class=fence>
  <tr>
    <td class=leftcontent>
        <div class=map> 
	  <!-- put the map of your choice here -->
	  <img src=images/worldmap.jpg usemap="#worldmap">
  
	  <map id="worldmap" name="worldmap">
	  <area shape=rect coords="266,53,345,150" 
                href="list.php?area=all" 
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
    </td>
    <td class=rightcontent>
      Select node by IP address
      <form align=middle action=dashboard.php method=get>
	<input type=text name=comonode size=21>
	<input type=image src=images/go.jpg>
      </form>
      <br>
      Add a new CoMo node
      <form align=middle action=nodeview.php method=get>
	<input type=text name=comonode size=21>
	<input type=image src=images/go.jpg >
      </form>
    </td>
  </tr>
</table>
</body>


<?php
    include("include/footer.php.inc");
?>


