# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 703_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `703_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-28 of the vulnerable file.

<?php

/*
 * Discover new hosts with snmp
 *******************************/

# verify that user is logged in
$User->check_user_session();

# scan disabled
if ($User->settings->enableSNMP!="1")           { $Result->show("danger", "SNMP module disbled", true); }
# subnet check
$subnet = $Subnets->fetch_subnet ("id", $_POST['subnetId']);
if ($subnet===false)                            { $Result->show("danger", "Invalid subnet Id", true);  }

# verify that user has write permissionss for subnet
if($Subnets->check_permission ($User->user, $_POST['subnetId']) != 3) 	{ $Result->show("danger", _('You do not have permissions to modify hosts in this subnet')."!", true, true); }

# set class
$Snmp = new phpipamSNMP ();

// no errors
error_reporting(E_ERROR);

// fetch all hosts to be scanned
$all_subnet_hosts = (array) $Addresses->fetch_subnet_addresses ($_POST['subnetId']);

// execute only if some exist
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,8 +4,8 @@
  * Discover new hosts with snmp
  *******************************/
 
-# verify that user is logged in
-$User->check_user_session();
+# Check we have been included and not called directly
+if (!isset($subnet_scan_execute_included)) { $Result->show("danger", _("Invalid request"), true); }
 
 # scan disabled
 if ($User->settings->enableSNMP!="1")           { $Result->show("danger", "SNMP module disbled", true); }
```
