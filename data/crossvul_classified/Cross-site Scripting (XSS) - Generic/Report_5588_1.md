# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5588_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5588_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-39 of the vulnerable file.

<?php

include_once "./functions.php";

$cluster_designator = "Cluster Overview";

///////////////////////////////////////////////////////////////////////////////
// Determine which context we are in. Context is not specifically specified
// so we have to figure it out ie. if vn(view_name) is present it's the views
// context, if cluster name is specified without a hostname it's cluster etc.
///////////////////////////////////////////////////////////////////////////////
// Blocking malicious CGI input.
$user['clustername'] = isset($_GET["c"]) ?
    escapeshellcmd( clean_string( rawurldecode($_GET["c"]) ) ) : NULL;
$user['gridname'] = isset($_GET["G"]) ?
    escapeshellcmd( clean_string( rawurldecode($_GET["G"]) ) ) : NULL;

$user['viewname'] = isset($_GET["vn"]) ?
    escapeshellcmd( clean_string( rawurldecode($_GET["vn"]) ) ) : '';

if($conf['case_sensitive_hostnames'] == 1) {
    $user['hostname'] = isset($_GET["h"]) ?
        escapeshellcmd( clean_string( rawurldecode($_GET["h"]) ) ) : NULL;
} else {
    $user['hostname'] = isset($_GET["h"]) ?
        strtolower( escapeshellcmd( clean_string( rawurldecode($_GET["h"]) ) ) ) : NULL;
}

$user['range'] = isset( $_GET["r"] ) && in_array($_GET["r"], array_keys( $conf['time_ranges'] ) ) ?
    escapeshellcmd( rawurldecode($_GET["r"])) : NULL;
$user['metricname'] = isset($_GET["m"]) ?
    escapeshellcmd( clean_string( rawurldecode($_GET["m"]) ) ) : NULL;
$user['metrictitle'] = isset($_GET["ti"]) ?
    escapeshellcmd( clean_string( rawurldecode($_GET["ti"]) ) ) : NULL;
$user['sort'] = isset($_GET["s"]) ?
    escapeshellcmd( clean_string( rawurldecode($_GET["s"]) ) ) : NULL;
$user['controlroom'] = isset($_GET["cr"]) ?
    escapeshellcmd( clean_string( rawurldecode($_GET["cr"]) ) ): NULL;
# Default value set in conf.php, Allow URL to overrride
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,8 +15,10 @@
 $user['gridname'] = isset($_GET["G"]) ?
     escapeshellcmd( clean_string( rawurldecode($_GET["G"]) ) ) : NULL;
 
-$user['viewname'] = isset($_GET["vn"]) ?
-    escapeshellcmd( clean_string( rawurldecode($_GET["vn"]) ) ) : '';
+$user['viewname'] = '';
+if ( isset($_GET["vn"]) &&  is_proper_view_name ($_GET["vn"]) ) {
+    $user['viewname'] = $_GET["vn"];
+}
 
 if($conf['case_sensitive_hostnames'] == 1) {
     $user['hostname'] = isset($_GET["h"]) ?
```
