# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 703_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `703_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<?php

/*
 * Update alive status of all hosts in subnet
 ***************************/

# validate subnetId and type
if(!is_numeric($_POST['subnetId']))                        { $Result->show("danger", "Invalid subnet Id", true); die(); }

# invoke CLI with threading support
$cmd = $Scan->php_exec." ".dirname(__FILE__) . '/../../../functions/scan/subnet-scan-icmp-execute.php'." 'update' ".$_POST['subnetId'];

# save result to $output
exec($cmd, $output, $retval);

# format result back to object
$output = array_values(array_filter($output));
$script_result = json_decode($output[0]);

# set blank values
if (!isset($script_result->values->alive) || is_null($script_result->values->alive) )	{ $script_result->values->alive = array(); }
if (!isset($script_result->values->dead)  || is_null($script_result->values->dead) )	{ $script_result->values->dead = array(); }

# set address types array
$Tools->get_addresses_types ();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,6 +3,9 @@
 /*
  * Update alive status of all hosts in subnet
  ***************************/
+
+# Check we have been included and not called directly
+if (!isset($subnet_scan_execute_included)) { $Result->show("danger", _("Invalid request"), true); }
 
 # validate subnetId and type
 if(!is_numeric($_POST['subnetId']))                        { $Result->show("danger", "Invalid subnet Id", true); die(); }
```
