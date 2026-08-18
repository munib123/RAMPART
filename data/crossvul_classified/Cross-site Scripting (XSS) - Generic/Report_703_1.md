# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 703_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `703_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-28 of the vulnerable file.

<?php

/*
 * Discover new hosts with telnet scan
 *******************************/

# verify that user is logged in
$User->check_user_session();

# get ports
if(strlen($_POST['port'])==0) 	  { $Result->show("danger", _('Please enter ports to scan').'!', true); }

//verify ports
$pcheck = explode(";", str_replace(",",";",$_POST['port']));
foreach($pcheck as $p) {
	if(!is_numeric($p)) {
		$Result->show("danger", _("Invalid port")." ($p)", true);
	}
}
$_POST['port'] = str_replace(";",",",$_POST['port']);

// verify subnetId
if(!is_numeric($_POST['subnetId'])) { $Result->show("danger", _('Invalid subnet Identifier').'!', true); }

# create csrf token
$csrf = $User->Crypto->csrf_cookie ("create", "scan");

# invoke CLI with threading support
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,17 +4,17 @@
  * Discover new hosts with telnet scan
  *******************************/
 
-# verify that user is logged in
-$User->check_user_session();
+# Check we have been included and not called directly
+if (!isset($subnet_scan_execute_included)) { $Result->show("danger", _("Invalid request"), true); }
 
 # get ports
-if(strlen($_POST['port'])==0) 	  { $Result->show("danger", _('Please enter ports to scan').'!', true); }
+if(empty($_POST['port'])) 	  { $Result->show("danger", _('Please enter ports to scan').'!', true); }
 
 //verify ports
 $pcheck = explode(";", str_replace(",",";",$_POST['port']));
 foreach($pcheck as $p) {
 	if(!is_numeric($p)) {
-		$Result->show("danger", _("Invalid port")." ($p)", true);
+		$Result->show("danger", _("Invalid port").' ('.escape_input($p).')', true);
 	}
 }
 $_POST['port'] = str_replace(";",",",$_POST['port']);
```
