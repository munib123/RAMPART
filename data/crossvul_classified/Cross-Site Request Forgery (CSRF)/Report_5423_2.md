# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in html
**Pair ID:** 5423_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5423_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```html
Lines 1-36 of the vulnerable file.

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>{title}</title>
</head>

<body>
<div flexy:start="here">
<script type="text/javascript">
<!--

function MMM_trackerAction(action, id)
{
    var f = document.getElementById('trackerAppendForm');
    
    f.t_action.value = action;
    f.t_id.value = id;
    f.submit();
    return false;
}

//-->
</script>
<div flexy:if="showReminder" class="errormessage"><img class="errormessage" src="{assetPath}/images/warning.gif" align="absmiddle">
<span class='tab-s'>You have unsaved changes on this page, make sure you press &quot;Save Changes&quot; when finished</span><br>
</div>
<form id="trackerAppendForm" class="section" method="post">
    <input type="hidden" name="clientid" value="{advertiser_id}" />
    <input type="hidden" name="trackerid" value="{tracker_id}" />
    <input type="hidden" name="t_action" />
    <input type="hidden" name="t_id"  />
    <input type="hidden" name="t_paused" value="{getPausedCodes()}" />
    <h3>Append tracker code</h3>
    <div flexy:foreach="codes,k,v" class="{cycleRow(#row#)}">
        <div class="label">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,7 +13,7 @@
 function MMM_trackerAction(action, id)
 {
     var f = document.getElementById('trackerAppendForm');
-    
+
     f.t_action.value = action;
     f.t_id.value = id;
     f.submit();
@@ -26,6 +26,7 @@
 <span class='tab-s'>You have unsaved changes on this page, make sure you press &quot;Save Changes&quot; when finished</span><br>
 </div>
 <form id="trackerAppendForm" class="section" method="post">
+    <input type="hidden" name="token" value="{csrf_token}" />
     <input type="hidden" name="clientid" value="{advertiser_id}" />
     <input type="hidden" name="trackerid" value="{tracker_id}" />
     <input type="hidden" name="t_action" />
```
