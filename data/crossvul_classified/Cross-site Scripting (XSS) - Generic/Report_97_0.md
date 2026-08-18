# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 97_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `97_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-25 of the vulnerable file.

<?php
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.

require_once(dirname(__FILE__) . "/../globals.php");
require_once $GLOBALS['OE_SITE_DIR'] . "/config.php";

$content_type = "text/plain";
$claim_file_dir = $GLOBALS['OE_SITE_DIR'] . "/edi/";

$fname = $_GET['key'];
$fname = preg_replace("[/]", "", $fname);
$fname = preg_replace("[\.\.]", "", $fname);
$fname = preg_replace("[\\\\]", "", $fname);

if (strtolower(substr($fname, (strlen($fname)-4))) == ".pdf") {
    $content_type = "application/pdf";
}

$fname = $claim_file_dir . $fname;

if (!file_exists($fname)) {
    echo xl("The claim file: ") . $_GET['key'] . xl(" could not be accessed.");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,8 +1,14 @@
 <?php
-// This program is free software; you can redistribute it and/or
-// modify it under the terms of the GNU General Public License
-// as published by the Free Software Foundation; either version 2
-// of the License, or (at your option) any later version.
+/**
+ * get_claim_file.php
+ *
+ * @package   OpenEMR
+ * @link      http://www.open-emr.org
+ * @author    Brady Miller <brady.g.miller@gmail.com>
+ * @copyright Copyright (c) 2018 Brady Miller <brady.g.miller@gmail.com>
+ * @license   https://github.com/openemr/openemr/blob/master/LICENSE GNU General Public License 3
+ */
+
 
 require_once(dirname(__FILE__) . "/../globals.php");
 require_once $GLOBALS['OE_SITE_DIR'] . "/config.php";
@@ -22,7 +28,7 @@
 $fname = $claim_file_dir . $fname;
 
 if (!file_exists($fname)) {
-    echo xl("The claim file: ") . $_GET['key'] . xl(" could not be accessed.");
+    echo xl("The claim file: ") . text($_GET['key']) . xl(" could not be accessed.");
 } else {
     $fp = fopen($fname, 'r');
 
```
