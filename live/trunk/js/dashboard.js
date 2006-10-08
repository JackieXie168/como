/*  $Id$  */

if (!document.getElementById)
    document.getElementById = function() { return null; }

function initializeConfigMenu(module) 
{
    var menuId = module + "MenuEdit";
    var triggerId = module + "TrigEdit";
    var menu = document.getElementById(menuId);
    var trigger = document.getElementById(triggerId);
    menu.style.display = "none"; 

    trigger.onclick = function() {
        var display = menu.style.display;
        if (display == "block")
	    menu.style.display = "none";
        else
	    menu.style.display = "block";
     
    }
}

function readCookie(name) 
{
    var nameEQ = name + "=";
    var ca = document.cookie.split(';');
    for(var i=0;i < ca.length;i++) {
	var c = ca[i];
	while (c.charAt(0)==' ') c = c.substring(1,c.length);
	    if (c.indexOf(nameEQ) == 0) 
		return c.substring(nameEQ.length,c.length);
    }
    return null;
}

function initializeMenu(module) 
{
    var menuId = module + "Menu";
    var triggerId = module + "Trig";
    var imageId = module + "Image"; 
    var menu = document.getElementById(menuId);
    var trigger = document.getElementById(triggerId);
    var image = document.getElementById(imageId); 
    var state = readCookie(module);
    menu.style.display = state; 
    var display = menu.style.display;
    image.src = (display == "block")? "../images/minus.gif" : "../images/plus.gif";

    trigger.onclick = function() {
        var display = menu.style.display;
	if (display == "block") { 
	    image.src = "../images/plus.gif"; 
	    menu.style.display = "none"; 
	    document.cookie = module + "=none"; 
        } else { 
	    image.src = "../images/minus.gif"; 
	    menu.style.display = "block"; 
	    document.cookie = module + "=block"; 
        } 
        return false;
    }
}

