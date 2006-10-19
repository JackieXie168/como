function clearText(thefield)
{
    if (thefield.defaultValue==thefield.value)
        thefield.value = ""
}

function ReloadPage()
{
        window.opener.location.reload(false);
        self.close();

}
