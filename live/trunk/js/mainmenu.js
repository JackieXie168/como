<!--  $Id$  -->
var xmlHttpMainMenu;

function createXMLHttpRequestMainMenu() {
    if (window.ActiveXObject) {
        xmlHttpMainMenu = new ActiveXObject("Microsoft.XMLHTTP");
    } else if (window.XMLHttpRequest) {
        xmlHttpMainMenu = new XMLHttpRequest();
    }
}

function startMenuRequest(val) {
    var val;
    createXMLHttpRequestMainMenu();
    xmlHttpMainMenu.onreadystatechange = handleMenuStateChange;
    xmlHttpMainMenu.open("GET", "include/submenu.php?sub=" + val, true);
    xmlHttpMainMenu.send(null);
}

function handleMenuStateChange() {
    if(xmlHttpMainMenu.readyState == 4 && xmlHttpMainMenu.status == 200)
        document.getElementById("results").innerHTML = xmlHttpMainMenu.responseText;
}

