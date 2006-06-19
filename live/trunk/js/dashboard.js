<!--  $Id:$  -->

window.onload = function() {
    initializeMenu("alertMenu", "alertTrig", "alertImage", "alert");
    initializeConfigMenu("alertMenuedit", "alertTrigedit", "alertedit");
    initializeMenu("topdestMenu", "topdestTrig", "topdestImage", "topdest");
    initializeConfigMenu("topdestMenuedit", "topdestTrigedit", "topdestedit");
    initializeMenu("topportsMenu", "topportsTrig", "topportsImage", "topports");
    initializeConfigMenu("topportsMenuedit", "topportsTrigedit","topportsedit");
}

if (!document.getElementById)
    document.getElementById = function() { return null; }

function initializeConfigMenu(menuId, triggerId, module) {
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

function readCookie(name) {
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

function initializeMenu(menuId, triggerId, imageId, module) {
    var menu = document.getElementById(menuId);
    var trigger = document.getElementById(triggerId);
    var image = document.getElementById(imageId); 
    var state = readCookie(module);
    menu.style.display = state; 
    var display = menu.style.display;
    image.src = (display == "block")? "images/minus.gif" : "images/plus.gif";

    trigger.onclick = function() {
        var display = menu.style.display;
	if (display == "block") { 
	    image.src = "images/plus.gif"; 
	    menu.style.display = "none"; 
	    document.cookie = module + "=none"; 
        } else { 
	    image.src = "images/minus.gif"; 
	    menu.style.display = "block"; 
	    document.cookie = module + "=block"; 
        } 
        return false;
    }
}

