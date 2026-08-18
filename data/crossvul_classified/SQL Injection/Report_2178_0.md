# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2178_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2178_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 26-67 of the vulnerable file.

    $_SESSION['error']['code'] = ERR_NOT_ALLOWED; //not allowed page
    include 'error.php';
    exit();
}

echo '
    <div class="title ui-widget-content ui-corner-all">'.$txt['admin'].'</div>
    <div style="width:900px;margin-left:50px; line-height:25px;height:100%;overflow:auto;">';

    // Div for tool info
    echo '
        <div id="CPM_infos" style="float:left;margin-top:10px;margin-left:15px;width:500px;">'.$txt['admin_info_loading'].'&nbsp;<img src="includes/images/ajax-loader.gif" alt="" /></div>';

     //div for information
     echo '
        <div style="float:right;width:300px;padding:10px;" class="ui-state-highlight ui-corner-all">
            <h3>Some instructions</h3>
            <span class="ui-icon ui-icon-wrench" style="float: left; margin-right: .3em;">&nbsp;</span>
                Access to <a target="_blank" href="http://www.teampass.net" style="font-weight:bold;font-style:italic;">TeamPass website</a><br />
            <span class="ui-icon ui-icon-wrench" style="float: left; margin-right: .3em;">&nbsp;</span>
                For any kind of Help and Support, please use the <a target="_blank" href="http://www.teampass.net/forum" style="font-weight:bold;font-style:italic;">Forum</a><br />
            <span class="ui-icon ui-icon-wrench" style="float: left; margin-right: .3em;">&nbsp;</span>
                You discovered a Bug or you have an improvement Proposal, please use the <a target="_blank" href="https://github.com/nilsteampassnet/TeamPass/issues" style="font-weight:bold;font-style:italic;">Github channel</a>. <i>If you are not sure, always use the Forum before to obtain a confirmation. This will prevent having to much open tickets at Github</i>.<br />
            <div style="text-align:center;margin-top:10px;">
                '.$txt['thku'].'
            </div>
        </div>';

    // Display the readme file
    $Fnm = "changelog.md";
if (file_exists($Fnm)) {
    $tab = file($Fnm);
    echo '
    <div style="float:left;width:900px;height:150px;overflow:auto;">
    <div style="float:left;" class="readme">
        <h3>'.$txt['changelog'].'</h3>';
    $show = false;
    $cnt = 0;
    while (list($cle,$val) = each($tab)) {
        if ($cnt < 30) {
            echo $val."<br />";
            $cnt ++;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,8 +43,6 @@
             <span class="ui-icon ui-icon-wrench" style="float: left; margin-right: .3em;">&nbsp;</span>
                 Access to <a target="_blank" href="http://www.teampass.net" style="font-weight:bold;font-style:italic;">TeamPass website</a><br />
             <span class="ui-icon ui-icon-wrench" style="float: left; margin-right: .3em;">&nbsp;</span>
-                For any kind of Help and Support, please use the <a target="_blank" href="http://www.teampass.net/forum" style="font-weight:bold;font-style:italic;">Forum</a><br />
-            <span class="ui-icon ui-icon-wrench" style="float: left; margin-right: .3em;">&nbsp;</span>
                 You discovered a Bug or you have an improvement Proposal, please use the <a target="_blank" href="https://github.com/nilsteampassnet/TeamPass/issues" style="font-weight:bold;font-style:italic;">Github channel</a>. <i>If you are not sure, always use the Forum before to obtain a confirmation. This will prevent having to much open tickets at Github</i>.<br />
             <div style="text-align:center;margin-top:10px;">
                 '.$txt['thku'].'
```
