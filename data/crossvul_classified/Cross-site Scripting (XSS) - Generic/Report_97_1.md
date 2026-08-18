# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 97_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `97_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-27 of the vulnerable file.

<?php
    // Copyright (C) 2006-2010 Rod Roark <rod@sunsetsystems.com>
    //
    // This program is free software; you can redistribute it and/or
    // modify it under the terms of the GNU General Public License
    // as published by the Free Software Foundation; either version 2
    // of the License, or (at your option) any later version.

    // This processes X12 835 remittances and produces a report.

    // Buffer all output so we can archive it to a file.
    ob_start();

require_once("../globals.php");
require_once("$srcdir/invoice_summary.inc.php");
require_once("$srcdir/sl_eob.inc.php");
require_once("$srcdir/parse_era.inc.php");
require_once("claim_status_codes.php");
require_once("adjustment_reason_codes.php");
require_once("remark_codes.php");
require_once("$srcdir/billing.inc");

    $debug = $_GET['debug'] ? 1 : 0; // set to 1 for debugging mode
    $paydate = parse_date($_GET['paydate']);
    $encount = 0;

    $last_ptname = '';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,15 +1,19 @@
 <?php
-    // Copyright (C) 2006-2010 Rod Roark <rod@sunsetsystems.com>
-    //
-    // This program is free software; you can redistribute it and/or
-    // modify it under the terms of the GNU General Public License
-    // as published by the Free Software Foundation; either version 2
-    // of the License, or (at your option) any later version.
-
-    // This processes X12 835 remittances and produces a report.
-
-    // Buffer all output so we can archive it to a file.
-    ob_start();
+/**
+ * This processes X12 835 remittances and produces a report.
+ *
+ * @package   OpenEMR
+ * @link      http://www.open-emr.org
+ * @author    Rod Roark <rod@sunsetsystems.com>
+ * @author    Brady Miller <brady.g.miller@gmail.com>
+ * @copyright Copyright (c) 2006-2010 Rod Roark <rod@sunsetsystems.com>
+ * @copyright Copyright (c) 2018 Brady Miller <brady.g.miller@gmail.com>
+ * @license   https://github.com/openemr/openemr/blob/master/LICENSE GNU General Public License 3
+ */
+
+
+// Buffer all output so we can archive it to a file.
+ob_start();
 
 require_once("../globals.php");
 require_once("$srcdir/invoice_summary.inc.php");
@@ -20,15 +24,15 @@
 require_once("remark_codes.php");
 require_once("$srcdir/billing.inc");
 
-    $debug = $_GET['debug'] ? 1 : 0; // set to 1 for debugging mode
-    $paydate = parse_date($_GET['paydate']);
-    $encount = 0;
-
-    $last_ptname = '';
-    $last_invnumber = '';
-    $last_code = '';
-    $invoice_total = 0.00;
-    $InsertionId;//last inserted ID of
+$debug = $_GET['debug'] ? 1 : 0; // set to 1 for debugging mode
+$paydate = parse_date($_GET['paydate']);
+$encount = 0;
+
+$last_ptname = '';
+$last_invnumber = '';
+$last_code = '';
+$invoice_total = 0.00;
+$InsertionId;//last inserted ID of
 
 ///////////////////////// Assorted Functions /////////////////////////
 
@@ -640,7 +644,7 @@
     $fnreport = "$nameprefix$namesuffix.html";
     $fhreport = fopen($fnreport, 'w');
     if (!$fhreport) {
-        die(xl("Cannot create") . " '$fnreport'");
+        die(xl("Cannot create") . " '" . text($fnreport) . "'");
     }
 }
 
@@ -738,12 +742,12 @@
 }
 ?>
 </script>
-<input type="hidden" name="paydate" value="<?php echo DateToYYYYMMDD($_REQUEST['paydate']);?>" />
-<input type="hidden" name="post_to_date" value="<?php echo DateToYYYYMMDD($_REQUEST['post_to_date']);?>" />
-<input type="hidden" name="deposit_date" value="<?php echo DateToYYYYMMDD($_REQUEST['deposit_date']);?>" />
-<input type="hidden" name="debug" value="<?php echo $_REQUEST['debug'];?>" />
-<input type="hidden" name="InsId" value="<?php echo $_REQUEST['InsId'];?>" />
-<input type="hidden" name="eraname" value="<?php echo $eraname?>" />
+<input type="hidden" name="paydate" value="<?php echo attr(DateToYYYYMMDD($_REQUEST['paydate'])); ?>" />
+<input type="hidden" name="post_to_date" value="<?php echo attr(DateToYYYYMMDD($_REQUEST['post_to_date'])); ?>" />
+<input type="hidden" name="deposit_date" value="<?php echo attr(DateToYYYYMMDD($_REQUEST['deposit_date'])); ?>" />
+<input type="hidden" name="debug" value="<?php echo attr($_REQUEST['debug']); ?>" />
+<input type="hidden" name="InsId" value="<?php echo attr($_REQUEST['InsId']); ?>" />
+<input type="hidden" name="eraname" value="<?php echo attr($eraname); ?>" />
 </form>
 </body>
 </html>
```
