<!--  $Id:$  -->

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
    xmlHttp.open("GET", "include/submenu.php?sub="+ val + 
                 "&webroot=<?=$G['WEBROOT']?>", true);
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
       position: absolute;
       top: 45px; 
       left: 5px; 
       width : 700px;
       margin-right: 3px; 
       margin-left: 3px; 
       border-bottom: 1px solid #ddd;
   }
   #menubar ul {
       padding : 0px ; 
       margin : 0px 0px 0px 0px;
       border : 0px 0px 0px 0px;
   }
   #menubar ul li {
       background-color : #FFF;
       display : inline;
   }
   #menubar ul li a:hover {
       background-color : #DDD;
       text-decoration : none;
   }
   .secmenubar {
       position: absolute;
       top: 23px; 
       left: 0px; 
       width : 730px;
       margin: 0px; 
       border-bottom: 1px solid #ddd;
   }
   .secmenubar ul {
       padding : 0px 3px 3px 3px;
       margin : 0px 0px 0px 0px;
       border : 0px 0px 0px 0px;
   }
   .secmenubar ul li {
       display : inline;
   }
   .secmenubar ul li a:hover {
       text-decoration : none;
   }
</style>

<div id=menubar>
  <ul>
    <!-- the &nbsp; allow the gray box around the text when hovering --> 
    <li>  
      <a href=# onclick="startRequest('system');">
      &nbsp;&nbsp;&nbsp;System&nbsp;&nbsp;&nbsp;</a>
    </li>
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

