var xmlLoadHttp;

function createXMLHttpLoadRequest() {
    if (window.ActiveXObject) {
        xmlLoadHttp = new ActiveXObject("Microsoft.XMLHTTP");
    }
    else if (window.XMLHttpRequest) {
        xmlLoadHttp = new XMLHttpRequest();
    }
}

function showLoading(url) {
    createXMLHttpLoadRequest();
    xmlLoadHttp.open("GET", url, true);
    xmlLoadHttp.onreadystatechange = loadingCallback;
    xmlLoadHttp.send(null);
}

function loadingCallback() {
    var content = document.getElementById("content");
    var loading = document.getElementById("loading");
    if ((xmlLoadHttp.readyState == 1) || (xmlLoadHttp.readyState == 2) || (xmlLoadHttp.readyState == 3)){
        loading.style.display = "block";
        xmlLoadHttp.onreadystatechange = loadingCallback;
    }
    if (xmlLoadHttp.readyState == 4) {
        loading.style.display = "none";
        if (xmlLoadHttp.status == 200) {
            content.innerHTML = xmlLoadHttp.responseText;
        }
    }
}
