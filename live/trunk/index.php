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


