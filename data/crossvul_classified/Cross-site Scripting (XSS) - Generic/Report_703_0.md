# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 703_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `703_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-31 of the vulnerable file.

<?php

/*
 * Discover new hosts with ping
 *******************************/

# verify that user is logged in
$User->check_user_session();

# create csrf token
$csrf = $User->Crypto->csrf_cookie ("create", "scan");

# validate subnetId and type
if(!is_numeric($_POST['subnetId']))                        { $Result->show("danger", "Invalid subnet Id", true); die(); }
if(!preg_match('/[^A-Za-z0-9-]*$/', $_POST['type']))       { $Result->show("danger", "Invalid scan type", true); die(); }


# invoke CLI with threading support
$cmd = $Scan->php_exec." ".dirname(__FILE__) . '/../../../functions/scan/subnet-scan-icmp-execute.php'." 'discovery' ".$_POST['subnetId'];

# save result to $output
exec($cmd, $output, $retval);

# format result back to object
$output = array_values(array_filter($output));
$script_result = json_decode($output[0]);

# if method is fping we need to check against existing hosts because it produces list of all ips !
if ($User->settings->scanPingType=="fping" && isset($script_result->values->alive)) {
	// fetch all hosts to be scanned
	$to_scan_hosts = $Scan->prepare_addresses_to_scan ("discovery", $_POST['subnetId']);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,11 +4,8 @@
  * Discover new hosts with ping
  *******************************/
 
-# verify that user is logged in
-$User->check_user_session();
-
-# create csrf token
-$csrf = $User->Crypto->csrf_cookie ("create", "scan");
+# Check we have been included and not called directly
+if (!isset($subnet_scan_execute_included)) { $Result->show("danger", _("Invalid request"), true); }
 
 # validate subnetId and type
 if(!is_numeric($_POST['subnetId']))                        { $Result->show("danger", "Invalid subnet Id", true); die(); }
```
