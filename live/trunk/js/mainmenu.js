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
    xmlHttp.open("GET", "include/submenu.php?sub=" + val, true);
    xmlHttp.send(null);
}

function handleStateChange() {
    if(xmlHttp.readyState == 4 && xmlHttp.status == 200)
        document.getElementById("results").innerHTML = xmlHttp.responseText;
}

