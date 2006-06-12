<!--  $Id$  -->

<style type="text/css">
  .sysinfobar{
    color :#FFF;
    width :100%;
    padding :2px;
    text-align:center;
  }
  .sysinfo {
    top: 0px;
    width: 100%;
    vertical-align:top;
    background-color: #FFF;
    margin: 2;
    padding-left: 5px;
    padding-right: 5px;
    font-size: 9pt;
    text-align:left;
  }
  .title {
    font-weight: bold;
    font-size: 9pt;
    padding-bottom: 3px;
    color: #475677;
  }
  .seperator {
    padding-left : 12px;
    border-left : 1px solid grey;
  }
  .customize {
    font-weight: bold;
    font-size: 9pt;
    color: #d71e48;
  }
</style>

  <div class="sysinfobar">
    <table class=sysinfo>
      <tr valign=top>
	<td valign=top class=seperator>
	  <div class=title>Location</div>
	  <?= $node->nodename ?><br>
	  <?= $node->nodeplace ?><br>
	</td>
	<td class=seperator>
	  <div class=title>System Information</div>
	  Software: <?= $node->version ?><br>
          Online Since: 
          <?= gmstrftime("%a %d %b %Y %T %Z", (int) $node->start);?><br>
	  Built: <?= $node->builddate ?>
	</td>
        <?
	if (isset($comment) && (!is_null($comment))){
          print "<td><div class=title>Notes:</div>";
          print "$comment<br></td>";
        }?>
      </tr>
    </table>
  </div>
