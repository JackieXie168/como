<!--  $Id$  -->

<?php 
    require_once "comolive.conf"; 

    $G = init_global(); 

    $submenu_param = "webroot=" . dirname($_SERVER['SCRIPT_NAME']); 
    /* XXX this is ugly! we should put the comonode in the $G array */
    if (isset($comonode)) 
	$submenu_param = $submenu_param . "&comonode=" . $comonode; 
    if ($G['ALLOWCUSTOMIZE']) 
	$submenu_param = $submenu_param . "&customize";
?> 

<script type="text/javascript">
var xmlHttp;

function createXMLHttpRequest() {
    if (window.ActiveXObject) {
        xmlHttp = new ActiveXObject("Microsoft.XMLHTTP");
    } else if (window.XMLHttpRequest) {
        xmlHttp = new XMLHttpRequest();
    }
}

function startRequest(val) {
    var val;
    createXMLHttpRequest();
    xmlHttp.onreadystatechange = handleStateChange;
    xmlHttp.open("GET", 
                 "include/submenu.php?sub=" + val + "&<?=$submenu_param?>", 
                 true);
    xmlHttp.send(null);
}

function handleStateChange() {
    if(xmlHttp.readyState == 4 && xmlHttp.status == 200) 
	document.getElementById("results").innerHTML = xmlHttp.responseText;
}
</script>

<div id=menubar>
  <ul>
    <!-- the &nbsp; allow the gray box around the text when hovering --> 
<? if (isset($comonode)) { ?>
    <li>  
      <a href=# onclick="startRequest('system');">
      &nbsp;&nbsp;&nbsp;System&nbsp;&nbsp;&nbsp;</a>
    </li>
<? } ?>
    <li>  
      <a href=# onclick="startRequest('view');">
      &nbsp;&nbsp;&nbsp;View&nbsp;&nbsp;&nbsp;</a>
    </li>
<!--
    <li>
      <a href=# onclick="startRequest('application');">
      &nbsp;&nbsp;&nbsp;Applications&nbsp;&nbsp;&nbsp;</a>
    </li>
-->
    <li>
      <a href=# onclick="startRequest('help');">
      &nbsp;&nbsp;&nbsp;Help&nbsp;&nbsp;&nbsp;</a>
    </li>
  </ul>
  <div id="results"></div>
</div>

