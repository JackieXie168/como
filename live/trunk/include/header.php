<!-- $Id$ --> 

<head>
  <title>CoMolive! - Intel Research Cambridge</title>
  <link rel="stylesheet" type="text/css" name="como" href="css/live.css">
  <link rel="shortcut icon" href="images/live_favicon.ico">
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
  <meta name="description" content="CoMolive!">
</head>

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
