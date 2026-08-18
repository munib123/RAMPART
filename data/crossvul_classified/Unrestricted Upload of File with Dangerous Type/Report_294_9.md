# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 294_9
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `294_9`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 1-28 of the vulnerable file.

<?php

////////////////////////////////////////////////////////////////////////////////
// THIS MODULE REPLACES cptcm_codes.php, hcpcs_codes.php AND icd9cm_codes.php.
////////////////////////////////////////////////////////////////////////////////

include_once("../../globals.php");
include_once("../../../custom/code_types.inc.php");

//the maximum number of records to pull out with the search:
$M = 30;

//the number of records to display before starting a second column:
$N = 15;

$code_type = $_GET['type'];
?>

<html>
<head>
<?php html_header_show();?>
<link rel="stylesheet" href="<?php echo $css_header;?>" type="text/css">

<!-- add jQuery support -->
<script type="text/javascript" src="<?php echo $GLOBALS['assets_static_relative']; ?>/jquery-min-1-2-2/index.js"></script>

</head>
<body class="body_bottom">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,8 +4,8 @@
 // THIS MODULE REPLACES cptcm_codes.php, hcpcs_codes.php AND icd9cm_codes.php.
 ////////////////////////////////////////////////////////////////////////////////
 
-include_once("../../globals.php");
-include_once("../../../custom/code_types.inc.php");
+require_once("../../globals.php");
+require_once("../../../custom/code_types.inc.php");
 
 //the maximum number of records to pull out with the search:
 $M = 30;
@@ -58,18 +58,18 @@
 
   // The above is obsolete now, fees come from the prices table:
     $sql = "SELECT codes.*, prices.pr_price FROM codes " .
-    "LEFT OUTER JOIN patient_data ON patient_data.pid = '$pid' " .
+    "LEFT OUTER JOIN patient_data ON patient_data.pid = ? " .
     "LEFT OUTER JOIN prices ON prices.pr_id = codes.id AND " .
     "prices.pr_selector = '' AND " .
     "prices.pr_level = patient_data.pricelevel " .
-    "WHERE (code_text LIKE '%" . $_POST["text"] . "%' OR " .
-    "code LIKE '%" . $_POST["text"] . "%') AND " .
-    "code_type = '" . $code_types[$code_type]['id'] . "' " .
+    "WHERE (code_text LIKE ? OR " .
+    "code LIKE ?) AND " .
+    "code_type = ? " .
     "ORDER BY code ".
     " LIMIT " . ($M + 1).
     "";
 
-    if ($res = sqlStatement($sql)) {
+    if ($res = sqlStatement($sql, array($pid, "%".$_POST["text"]."%", "%".$_POST["text"]."%", $code_types[$code_type]['id']))) {
         for ($iter=0; $row=sqlFetchArray($res); $iter++) {
             $result[$iter] = $row;
         }
```
