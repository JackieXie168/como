<?php
?>
<script type="text/javascript">
var xmlHttp;

function createXMLHttpRequest() {
    if (window.ActiveXObject) {
        xmlHttp = new ActiveXObject("Microsoft.XMLHTTP");
    }
    else if (window.XMLHttpRequest) {
        xmlHttp = new XMLHttpRequest();
    }
}

function startRequest(val) {
    var val;
    createXMLHttpRequest();
    xmlHttp.onreadystatechange = handleStateChange;
    xmlHttp.open("GET", "include/submenu.php?sub="+ val + 
                 "&webroot=<?=$WEBROOT?>", true);
    xmlHttp.send(null);
}

function handleStateChange() {
    if(xmlHttp.readyState == 4) {
        if(xmlHttp.status == 200) {
            document.getElementById("results").innerHTML = xmlHttp.responseText;
        }
    }
}
</script>
<style>
   a {
       text-decoration : none;
   }
   #menubar {
       width : 800px;
       
   }
   #menubar ul {
       padding : 3px 3px 3px 3px;
       margin : 0px 0px 0px 0px;
       border : 0px 0px 0px 0px;
   }
   #menubar ul li {
       background-color : #DDD;
       display : inline;
       padding : 2px 8px 2px 8px;
   }
   #menubar ul li a:hover {
       color : #ffa;
       text-decoration : none;
   }
   .secmenubar {
       width : 800px;
       margin-left : 0px;
       margin-top : 0px;
   }
   .secmenubar ul {
       padding : 3px 3px 3px 3px;
       margin : 0px 0px 0px 0px;
       border : 0px 0px 0px 0px;
   }
   .secmenubar ul li {
       background-color : #DDD;
       display : inline;
   }
   .secmenubar ul li a:hover {
       color : #ffa;
       text-decoration : none;
   }

</style>
<div id=menubar>
    <ul>
      <li><a href=# onclick="startRequest('system');">System</a></li>
      <li><a href=# onclick="startRequest('application');">Applications</a></li>
      <li><a href=# onclick="startRequest('help');">Help</a></li>
    </ul>
    <div id="results"></div>
</div>

