# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1134_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1134_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-24 of the vulnerable file.

<?php

if (isset($_REQUEST['managerdisplay'])){
  $managerdisplay = $_REQUEST['managerdisplay'];
  $subhead = '<h2>'._("Manager").' '.$managerdisplay.'</h2>';
  $delURL = '?display=manager&amp;managerdisplay='.$managerdisplay.'&amp;action=delete';
  //get details for this manager
  $thisManager = manager_get($managerdisplay);
  //create variables
  extract(manager_format_out($thisManager));
} else {
  $subhead = '<h2>'._("Add Manager").'</h2>';
  $delURL = '';
  $rall = 1;
  $wall = 1;
  $name = '';
  $secret = md5(openssl_random_pseudo_bytes(16));
  $deny = '0.0.0.0/0.0.0.0';
  $permit = '127.0.0.1/255.255.255.0';
}
$permtypes = array(
  'system' => _("system"),
  'call' => _("call"),
  'log' => _("log"),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 <?php
 
 if (isset($_REQUEST['managerdisplay'])){
-  $managerdisplay = $_REQUEST['managerdisplay'];
+  $managerdisplay = htmlentities($_REQUEST['managerdisplay'], ENT_QUOTES);
   $subhead = '<h2>'._("Manager").' '.$managerdisplay.'</h2>';
   $delURL = '?display=manager&amp;managerdisplay='.$managerdisplay.'&amp;action=delete';
   //get details for this manager
```
