<!-- $Id$ --> 

<head>
  <title>CoMolive! - Intel Research Cambridge</title>
  <link rel="stylesheet" type="text/css" name="como" href="css/live.css">
  <link rel="shortcut icon" href="images/live_favicon.ico">
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
  <meta name="description" content="CoMolive!">
</head>

<!-- This javascript is to handle the drop down menu. The content of 
     the menu can be found in include/menulist.php.inc -->
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

<body onload="javascript:clearmenu('smenu');">

<div id=header>
  <img onmouseover="javascript:clearmenu('smenu')" src=images/comolive.jpg>
  <div class=goback>
    - <a href="/">Home</a> > <a href="/live"> CoMolive! </a>
    <?php 
       if (!is_null($nodename)) { 
	   print "> $nodename"; 
       }
    ?>
  </div>
</div>
